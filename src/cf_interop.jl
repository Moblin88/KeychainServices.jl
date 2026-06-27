# ── CF / Security framework interop ───────────────────────────────────────────
#
# This file is only included on Apple platforms (@static if Sys.isapple() in
# KeychainServices.jl). It provides:
#
#   • _sec(sym)                — load a Security/CF framework constant by symbol
#   • _cf_dict(f, pairs_iter)  — build a temporary CFMutableDictionary, call f, release
#   • _cf_dict_set!            — type-dispatched value marshaling into a CF dict
#   • _sec_item_*              — thin wrappers over SecItemAdd/CopyMatching/Update/Delete
#   • CF → Julia converters    — CFString, CFData, CFBoolean, CFDate
#   • probe_data_protection_entitlement — runtime entitlement check
#
# ──────────────────────────────────────────────────────────────────────────────

# OSStatus constants from <Security/SecBase.h>
const errSecSuccess              = Int32(0)
const errSecItemNotFound         = Int32(-25300)
const errSecDuplicateItem        = Int32(-25299)
const errSecAuthFailed           = Int32(-25293)
const errSecInteractionNotAllowed= Int32(-25308)
const errSecMissingEntitlement   = Int32(-34018)

# Load a Security / CoreFoundation framework constant by its symbol name.
# Each kSecXxx is declared `extern CFTypeRef kSecXxx` in the framework headers,
# so the symbol address holds a pointer-sized value (the CFTypeRef itself).
_sec(sym::Symbol) = unsafe_load(cglobal(sym, Ptr{Cvoid}))

function _classify_keychain_error(status::Int32)
    status == errSecDuplicateItem        && return KeychainOperationError("Keychain item already exists (errSecDuplicateItem)")
    status == errSecItemNotFound         && return KeychainItemNotFoundError("Keychain item not found (errSecItemNotFound)")
    status == errSecAuthFailed           && return KeychainPermissionError("Keychain authentication failed (errSecAuthFailed)")
    status == errSecInteractionNotAllowed && return KeychainPermissionError("Keychain interaction not allowed (errSecInteractionNotAllowed)")
    status == errSecMissingEntitlement   && return KeychainPermissionError("Missing keychain entitlement — the process needs keychain-access-groups or com.apple.application-identifier (errSecMissingEntitlement)")
    return KeychainOperationError("Keychain operation failed with OSStatus $status")
end

# ── CF dict builder ────────────────────────────────────────────────────────────

"""
    _cf_dict(f, pairs_iter)

Build a `CFMutableDictionary` from `pairs_iter` (anything that responds to `pairs`
or is directly iterable as `(Symbol, Any)` pairs), call `f(dict)`, then release the
dictionary. Values are marshaled into CF objects via `_cf_dict_set!` dispatch.
"""
function _cf_dict(f, init)
    key_cb = cglobal(:kCFTypeDictionaryKeyCallBacks, Cvoid)
    val_cb = cglobal(:kCFTypeDictionaryValueCallBacks, Cvoid)

    dict = @ccall CFDictionaryCreateMutable(
        C_NULL::Ptr{Cvoid},
        Int32(0)::Int32,
        key_cb::Ptr{Cvoid},
        val_cb::Ptr{Cvoid}
    )::Ptr{Cvoid}
    dict == C_NULL && throw(KeychainOperationError("CFDictionaryCreateMutable returned NULL"))

    try
        for (k, v) in init
            _cf_dict_set!(dict, k, v)
        end
        return f(dict)
    finally
        @ccall CFRelease(dict::Ptr{Cvoid})::Cvoid
    end
end

# ── _cf_dict_set! dispatch ─────────────────────────────────────────────────────

function _cf_dict_set!(dict::Ptr{Cvoid}, key::Symbol, value::Symbol)
    @ccall CFDictionarySetValue(
        dict::Ptr{Cvoid}, _sec(key)::Ptr{Cvoid}, _sec(value)::Ptr{Cvoid}
    )::Cvoid
end

function _cf_dict_set!(dict::Ptr{Cvoid}, key::Symbol, value::AbstractString)
    cfstr = @ccall CFStringCreateWithCString(
        C_NULL::Ptr{Cvoid}, String(value)::Cstring, UInt32(4)::UInt32  # kCFStringEncodingUTF8
    )::Ptr{Cvoid}
    cfstr == C_NULL && throw(KeychainOperationError("CFStringCreateWithCString returned NULL"))
    try
        @ccall CFDictionarySetValue(dict::Ptr{Cvoid}, _sec(key)::Ptr{Cvoid}, cfstr::Ptr{Cvoid})::Cvoid
    finally
        @ccall CFRelease(cfstr::Ptr{Cvoid})::Cvoid
    end
end

function _cf_dict_set!(dict::Ptr{Cvoid}, key::Symbol, value::Bool)
    cfbool = value ? _sec(:kCFBooleanTrue) : _sec(:kCFBooleanFalse)
    @ccall CFDictionarySetValue(dict::Ptr{Cvoid}, _sec(key)::Ptr{Cvoid}, cfbool::Ptr{Cvoid})::Cvoid
end

function _cf_dict_set!(dict::Ptr{Cvoid}, key::Symbol, value::Ptr{Cvoid})
    @ccall CFDictionarySetValue(dict::Ptr{Cvoid}, _sec(key)::Ptr{Cvoid}, value::Ptr{Cvoid})::Cvoid
end

function _cf_dict_set!(dict::Ptr{Cvoid}, key::Symbol, value::AbstractVector{UInt8})
    ptr = isempty(value) ? C_NULL : pointer(value)
    cfdata = GC.@preserve value begin
        @ccall CFDataCreate(
            C_NULL::Ptr{Cvoid}, ptr::Ptr{Cuchar}, Int64(length(value))::Int64
        )::Ptr{Cvoid}
    end
    cfdata == C_NULL && throw(KeychainOperationError("CFDataCreate returned NULL"))
    try
        @ccall CFDictionarySetValue(dict::Ptr{Cvoid}, _sec(key)::Ptr{Cvoid}, cfdata::Ptr{Cvoid})::Cvoid
    finally
        @ccall CFRelease(cfdata::Ptr{Cvoid})::Cvoid
    end
end

function _cf_dict_set!(dict::Ptr{Cvoid}, key::Symbol, value::Base.SecretBuffer)
    pos = position(value)
    bytes = try
        seekstart(value)
        read(value)
    finally
        seek(value, pos)
    end
    try
        _cf_dict_set!(dict, key, bytes)
    finally
        Base.securezero!(bytes)
    end
end

# Marshal an AccessControlItem into a SecAccessControlRef.
function _cf_dict_set!(dict::Ptr{Cvoid}, key::Symbol, value::AccessControlItem)
    error_ref = Ref{Ptr{Cvoid}}(C_NULL)
    acc_ref = @ccall SecAccessControlCreateWithFlags(
        C_NULL::Ptr{Cvoid},
        _sec(value.accessible)::Ptr{Cvoid},
        value.flags::UInt64,
        error_ref::Ref{Ptr{Cvoid}}
    )::Ptr{Cvoid}
    if acc_ref == C_NULL
        throw(KeychainOperationError(
            "SecAccessControlCreateWithFlags failed for $(value.accessible)" *
            (error_ref[] != C_NULL ? ": " * something(_cfstring_to_string(
                @ccall CFErrorCopyDescription(error_ref[]::Ptr{Cvoid})::Ptr{Cvoid}
            ), "unknown error") : "")
        ))
    end
    try
        @ccall CFDictionarySetValue(dict::Ptr{Cvoid}, _sec(key)::Ptr{Cvoid}, acc_ref::Ptr{Cvoid})::Cvoid
    finally
        @ccall CFRelease(acc_ref::Ptr{Cvoid})::Cvoid
    end
end

# Open a legacy keychain file and store the SecKeychainRef in the dict.
function _cf_dict_set!(dict::Ptr{Cvoid}, key::Symbol, value::FileKeychain)
    kc_ref = Ref{Ptr{Cvoid}}(C_NULL)
    status = @ccall SecKeychainOpen(value.path::Cstring, kc_ref::Ref{Ptr{Cvoid}})::Int32
    status != 0 && throw(KeychainOperationError(
        "SecKeychainOpen(\"$(value.path)\") failed with OSStatus $status"
    ))
    kc = kc_ref[]
    kc == C_NULL && throw(KeychainOperationError("SecKeychainOpen returned a NULL ref for \"$(value.path)\""))
    try
        @ccall CFDictionarySetValue(dict::Ptr{Cvoid}, _sec(key)::Ptr{Cvoid}, kc::Ptr{Cvoid})::Cvoid
    finally
        @ccall CFRelease(kc::Ptr{Cvoid})::Cvoid
    end
end

# ── SecItem CRUD wrappers ──────────────────────────────────────────────────────

function _sec_item_add(query_init)
    _cf_dict(query_init) do dict
        status = @ccall SecItemAdd(dict::Ptr{Cvoid}, C_NULL::Ptr{Cvoid})::Int32
        status != errSecSuccess && throw(_classify_keychain_error(status))
    end
    return nothing
end

function _sec_item_copy_matching(query_init)
    _cf_dict(query_init) do dict
        result_ref = Ref{Ptr{Cvoid}}(C_NULL)
        status = @ccall SecItemCopyMatching(dict::Ptr{Cvoid}, result_ref::Ref{Ptr{Cvoid}})::Int32
        status != errSecSuccess && throw(_classify_keychain_error(status))
        return result_ref[]
    end
end

function _sec_item_update(query_init, attrs_init)
    _cf_dict(query_init) do query
        _cf_dict(attrs_init) do attrs
            status = @ccall SecItemUpdate(query::Ptr{Cvoid}, attrs::Ptr{Cvoid})::Int32
            status != errSecSuccess && throw(_classify_keychain_error(status))
        end
    end
    return nothing
end

function _sec_item_delete(query_init)
    _cf_dict(query_init) do dict
        status = @ccall SecItemDelete(dict::Ptr{Cvoid})::Int32
        status != errSecSuccess && throw(_classify_keychain_error(status))
    end
    return nothing
end

# ── CF dict reader ─────────────────────────────────────────────────────────────

function _cf_dict_get(dict::Ptr{Cvoid}, key::Symbol)
    @ccall CFDictionaryGetValue(dict::Ptr{Cvoid}, _sec(key)::Ptr{Cvoid})::Ptr{Cvoid}
end

# ── CF → Julia converters ──────────────────────────────────────────────────────

function _cfstring_to_string(cfstr::Ptr{Cvoid})
    cfstr == C_NULL && return nothing
    cstr = @ccall CFStringGetCStringPtr(cfstr::Ptr{Cvoid}, UInt32(4)::UInt32)::Cstring
    if cstr != C_NULL
        return unsafe_string(cstr)
    end
    # Slow path: CFStringGetCStringPtr may return NULL for some encodings.
    len = @ccall CFStringGetLength(cfstr::Ptr{Cvoid})::Int64
    buf = Vector{UInt8}(undef, len * 4 + 1)
    ok = @ccall CFStringGetCString(
        cfstr::Ptr{Cvoid}, pointer(buf)::Ptr{Cuchar}, Int64(length(buf))::Int64, UInt32(4)::UInt32
    )::Bool
    ok || return nothing
    return unsafe_string(pointer(buf))
end

function _cfboolean_to_bool(cfbool::Ptr{Cvoid})
    cfbool == C_NULL && return nothing
    return @ccall CFBooleanGetValue(cfbool::Ptr{Cvoid})::Bool
end

# CFAbsoluteTime epoch: 2001-01-01T00:00:00 UTC
const _CF_EPOCH = DateTime(2001, 1, 1, 0, 0, 0)

function _cfdate_to_datetime(cfdate::Ptr{Cvoid})
    cfdate == C_NULL && return nothing
    abs_time = @ccall CFDateGetAbsoluteTime(cfdate::Ptr{Cvoid})::Float64
    return _CF_EPOCH + Dates.Millisecond(round(Int64, abs_time * 1000))
end

function _cfdata_to_bytes(cfdata::Ptr{Cvoid})
    cfdata == C_NULL && return nothing
    len  = @ccall CFDataGetLength(cfdata::Ptr{Cvoid})::Int64
    bytes_ptr = @ccall CFDataGetBytePtr(cfdata::Ptr{Cvoid})::Ptr{Cuchar}
    out = Vector{UInt8}(undef, Int(len))
    len > 0 && unsafe_copyto!(pointer(out), Ptr{UInt8}(bytes_ptr), Int(len))
    return out
end

function _cfdata_to_secretbuffer(cfdata::Ptr{Cvoid})
    len  = @ccall CFDataGetLength(cfdata::Ptr{Cvoid})::Int64
    bytes_ptr = @ccall CFDataGetBytePtr(cfdata::Ptr{Cvoid})::Ptr{Cuchar}
    buf = Vector{UInt8}(undef, Int(len))
    try
        len > 0 && unsafe_copyto!(pointer(buf), Ptr{UInt8}(bytes_ptr), Int(len))
        return Base.SecretBuffer!(buf)
    catch
        Base.securezero!(buf)
        rethrow()
    end
end

function _cf_constant_to_symbol(cf_value::Ptr{Cvoid}, constants)
    cf_value == C_NULL && return nothing
    for sym in constants
        _sec(sym) == cf_value && return sym
    end
    return nothing
end

# ── Entitlement probe ──────────────────────────────────────────────────────────

"""
    probe_data_protection_entitlement() -> Bool

Returns `true` when the current process has the entitlements required to write to
the Data Protection keychain, `false` otherwise.

This is determined at runtime by issuing a `SecItemAdd` call (the same underlying
API used by [`add_item!`](@ref)) with `kSecUseDataProtectionKeychain = true` against
a service name guaranteed not to conflict. An `errSecSuccess` or `errSecDuplicateItem`
response confirms that write access is available; `errSecMissingEntitlement` (-34018)
confirms it is not. The probe item is deleted on success.
"""
function probe_data_protection_entitlement()::Bool
    probe_service = "KeychainServices.jl.entitlement.probe.$(getpid()).$(time_ns())"

    add_pairs = Pair{Symbol,Any}[
        :kSecClass                    => :kSecClassGenericPassword,
        :kSecAttrService              => probe_service,
        :kSecAttrAccount              => "probe",
        :kSecUseDataProtectionKeychain => true,
        :kSecValueData                => UInt8[0x70],  # minimal CFData
    ]

    status = _cf_dict(add_pairs) do dict
        @ccall SecItemAdd(dict::Ptr{Cvoid}, C_NULL::Ptr{Cvoid})::Int32
    end

    if status == errSecSuccess || status == errSecDuplicateItem
        del_pairs = Pair{Symbol,Any}[
            :kSecClass                    => :kSecClassGenericPassword,
            :kSecAttrService              => probe_service,
            :kSecAttrAccount              => "probe",
            :kSecUseDataProtectionKeychain => true,
        ]
        _cf_dict(del_pairs) do dict
            @ccall SecItemDelete(dict::Ptr{Cvoid})::Int32
        end
        return true
    end

    return false
end
