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

const _AUTH_UI_VALUES = (
    :kSecUseAuthenticationUIAllow,
    :kSecUseAuthenticationUIFail,
    :kSecUseAuthenticationUISkip,
)

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
    _cf_dict(f, pairs_iter, target::KeychainTarget = LoginKeychain())

Build a `CFMutableDictionary` from `pairs_iter` (iterable of `(Symbol, Any)`
pairs), apply the keychain target, call `f(dict)`, then release the dictionary.
Values are marshaled into CF objects via `_julia_to_cf` dispatch.
"""
function _cf_dict(f, init, target::KeychainTarget = LoginKeychain())
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
        _apply_keychain_target!(dict, target)
        return f(dict)
    finally
        @ccall CFRelease(dict::Ptr{Cvoid})::Cvoid
    end
end

# ── Julia → CF marshalling ─────────────────────────────────────────────────────
#
# _julia_to_cf(f, value) creates the appropriate CF object for value, calls
# f(cf_ptr), then releases it. Types that borrow an existing CF constant (Symbol,
# Bool, Ptr{Cvoid}) call f directly with no allocation or release.

_julia_to_cf(f, value::Symbol)     = f(_sec(value))
_julia_to_cf(f, value::Bool)       = f(value ? _sec(:kCFBooleanTrue) : _sec(:kCFBooleanFalse))
_julia_to_cf(f, value::Ptr{Cvoid}) = f(value)

function _julia_to_cf(f, value::AbstractString)
    cfstr = @ccall CFStringCreateWithCString(
        C_NULL::Ptr{Cvoid}, String(value)::Cstring, UInt32(4)::UInt32  # kCFStringEncodingUTF8
    )::Ptr{Cvoid}
    cfstr == C_NULL && throw(KeychainOperationError("CFStringCreateWithCString returned NULL"))
    try
        f(cfstr)
    finally
        @ccall CFRelease(cfstr::Ptr{Cvoid})::Cvoid
    end
end

function _julia_to_cf(f, value::AbstractVector{UInt8})
    ptr    = isempty(value) ? C_NULL : pointer(value)
    cfdata = GC.@preserve value @ccall CFDataCreate(
        C_NULL::Ptr{Cvoid}, ptr::Ptr{Cuchar}, Int64(length(value))::Int64
    )::Ptr{Cvoid}
    cfdata == C_NULL && throw(KeychainOperationError("CFDataCreate returned NULL"))
    try
        f(cfdata)
    finally
        @ccall CFRelease(cfdata::Ptr{Cvoid})::Cvoid
    end
end

function _julia_to_cf(f, value::Integer)
    v = Int32(value)
    cfnum = GC.@preserve v @ccall CFNumberCreate(
        C_NULL::Ptr{Cvoid}, Int32(3)::Int32, Ref(v)::Ptr{Int32}
    )::Ptr{Cvoid}
    cfnum == C_NULL && throw(KeychainOperationError("CFNumberCreate returned NULL"))
    try
        f(cfnum)
    finally
        @ccall CFRelease(cfnum::Ptr{Cvoid})::Cvoid
    end
end

function _julia_to_cf(f, value::AccessControlItem)
    error_ref = Ref{Ptr{Cvoid}}(C_NULL)
    acc_ref   = @ccall SecAccessControlCreateWithFlags(
        C_NULL::Ptr{Cvoid},
        _sec(value.accessible)::Ptr{Cvoid},
        value.flags::UInt64,
        error_ref::Ref{Ptr{Cvoid}},
    )::Ptr{Cvoid}
    if acc_ref == C_NULL
        msg = "SecAccessControlCreateWithFlags failed for $(value.accessible)"
        if error_ref[] != C_NULL
            desc_cf = @ccall CFErrorCopyDescription(error_ref[]::Ptr{Cvoid})::Ptr{Cvoid}
            detail  = desc_cf != C_NULL ? something(_cf_to_julia(desc_cf, String), "unknown error") : "unknown error"
            desc_cf != C_NULL && @ccall CFRelease(desc_cf::Ptr{Cvoid})::Cvoid
            @ccall CFRelease(error_ref[]::Ptr{Cvoid})::Cvoid
            msg *= ": $detail"
        end
        throw(KeychainOperationError(msg))
    end
    try
        f(acc_ref)
    finally
        @ccall CFRelease(acc_ref::Ptr{Cvoid})::Cvoid
    end
end

# ── _cf_dict_set! ──────────────────────────────────────────────────────────────

# Generic: marshal value to CF, set it under key, release.
function _cf_dict_set!(dict::Ptr{Cvoid}, key::Symbol, value)
    _julia_to_cf(value) do cf_val
        @ccall CFDictionarySetValue(dict::Ptr{Cvoid}, _sec(key)::Ptr{Cvoid}, cf_val::Ptr{Cvoid})::Cvoid
    end
end

# ── _apply_keychain_target! ────────────────────────────────────────────────────
#
# Called by _cf_dict after the pairs loop to apply keychain routing.
# Login and DataProtection are handled entirely via their pairs entries;
# FileKeychain requires opening a handle and setting two keys.

_apply_keychain_target!(::Ptr{Cvoid}, ::LoginKeychain)          = nothing

function _apply_keychain_target!(dict::Ptr{Cvoid}, ::DataProtectionKeychain)
    _cf_dict_set!(dict, :kSecUseDataProtectionKeychain, true)
end

function _apply_keychain_target!(dict::Ptr{Cvoid}, kc::FileKeychain)
    kc_ref = Ref{Ptr{Cvoid}}(C_NULL)
    status = @ccall SecKeychainOpen(kc.path::Cstring, kc_ref::Ref{Ptr{Cvoid}})::Int32
    status != 0 && throw(KeychainOperationError(
        "SecKeychainOpen(\"$(kc.path)\") failed with OSStatus $status"
    ))
    kc_ref_val = kc_ref[]
    kc_ref_val == C_NULL && throw(KeychainOperationError(
        "SecKeychainOpen returned a NULL ref for \"$(kc.path)\""
    ))
    try
        # kSecUseKeychain: for SecItemAdd
        @ccall CFDictionarySetValue(
            dict::Ptr{Cvoid}, _sec(:kSecUseKeychain)::Ptr{Cvoid}, kc_ref_val::Ptr{Cvoid}
        )::Cvoid

        # kSecMatchSearchList: for SecItemCopyMatching / SecItemUpdate / SecItemDelete
        cb  = cglobal(:kCFTypeArrayCallBacks, Cvoid)
        arr = GC.@preserve kc_ref_val @ccall CFArrayCreate(
            C_NULL::Ptr{Cvoid}, Ref(kc_ref_val)::Ptr{Ptr{Cvoid}}, Int64(1)::Int64, cb::Ptr{Cvoid}
        )::Ptr{Cvoid}
        arr == C_NULL && throw(KeychainOperationError("CFArrayCreate returned NULL"))
        try
            @ccall CFDictionarySetValue(
                dict::Ptr{Cvoid}, _sec(:kSecMatchSearchList)::Ptr{Cvoid}, arr::Ptr{Cvoid}
            )::Cvoid
        finally
            @ccall CFRelease(arr::Ptr{Cvoid})::Cvoid
        end
    finally
        @ccall CFRelease(kc_ref_val::Ptr{Cvoid})::Cvoid
    end
end

# ── Secret IO helper ───────────────────────────────────────────────────────────

"""
    _with_secret_bytes(f, secret)

Extract secret bytes from `secret` and call `f(bytes::AbstractVector{UInt8})`,
then clean up any temporary allocation.

- `IO`: reads from the current position (`nbytes` bytes or all remaining),
  calls `f`, then `securezero!`s the temporary copy. The `IO` position
  advances naturally; no other modifications are made.
- `AbstractVector{UInt8}`: calls `f` directly with the vector — no copy, no
  zeroing. Core Foundation makes its own copy; the caller owns the original.
- `AbstractString`: encodes to `Vector{UInt8}` via `codeunits`, calls `f`,
  then `securezero!`s the copy.
"""
function _with_secret_bytes(f, io::IO, nbytes::Union{Int, Nothing} = nothing)
    bytes = nbytes === nothing ? read(io) : read(io, nbytes)
    try
        f(bytes)
    finally
        Base.securezero!(bytes)
    end
end

function _with_secret_bytes(f, v::AbstractVector{UInt8}, ::Union{Int, Nothing} = nothing)
    f(v)
end

function _with_secret_bytes(f, s::AbstractString, ::Union{Int, Nothing} = nothing)
    bytes = Vector{UInt8}(codeunits(s))
    try
        f(bytes)
    finally
        Base.securezero!(bytes)
    end
end

# ── SecItem CRUD wrappers ──────────────────────────────────────────────────────

function _sec_item_add(query_init, target::KeychainTarget = LoginKeychain())
    _cf_dict(query_init, target) do dict
        status = @ccall SecItemAdd(dict::Ptr{Cvoid}, C_NULL::Ptr{Cvoid})::Int32
        status != errSecSuccess && throw(_classify_keychain_error(status))
    end
    return nothing
end

function _sec_item_copy_matching(query_init, target::KeychainTarget = LoginKeychain())
    _cf_dict(query_init, target) do dict
        result_ref = Ref{Ptr{Cvoid}}(C_NULL)
        status = @ccall SecItemCopyMatching(dict::Ptr{Cvoid}, result_ref::Ref{Ptr{Cvoid}})::Int32
        status != errSecSuccess && throw(_classify_keychain_error(status))
        return result_ref[]
    end
end

# Returns a CFArrayRef (caller must CFRelease), or C_NULL when no items match.
function _sec_item_copy_all(query_init, target::KeychainTarget = LoginKeychain())
    _cf_dict(query_init, target) do dict
        result_ref = Ref{Ptr{Cvoid}}(C_NULL)
        status = @ccall SecItemCopyMatching(dict::Ptr{Cvoid}, result_ref::Ref{Ptr{Cvoid}})::Int32
        status == errSecItemNotFound && return C_NULL
        status != errSecSuccess && throw(_classify_keychain_error(status))
        return result_ref[]
    end
end

function _sec_item_update(query_init, attrs_init, target::KeychainTarget = LoginKeychain())
    _cf_dict(query_init, target) do query
        _cf_dict(attrs_init) do attrs
            status = @ccall SecItemUpdate(query::Ptr{Cvoid}, attrs::Ptr{Cvoid})::Int32
            status != errSecSuccess && throw(_classify_keychain_error(status))
        end
    end
    return nothing
end

function _sec_item_delete(query_init, target::KeychainTarget = LoginKeychain())
    _cf_dict(query_init, target) do dict
        status = @ccall SecItemDelete(dict::Ptr{Cvoid})::Int32
        status != errSecSuccess && throw(_classify_keychain_error(status))
    end
    return nothing
end

# ── CF dict reader ─────────────────────────────────────────────────────────────

function _cf_dict_get(dict::Ptr{Cvoid}, key::Symbol)
    @ccall CFDictionaryGetValue(dict::Ptr{Cvoid}, _sec(key)::Ptr{Cvoid})::Ptr{Cvoid}
end

function _cf_dict_get(dict::Ptr{Cvoid}, key::Symbol, T::Type, args...)
    p = _cf_dict_get(dict, key)
    p == C_NULL ? nothing : _cf_to_julia(p, T, args...)
end

# ── CF → Julia converters ──────────────────────────────────────────────────────

function _cf_to_julia(p::Ptr{Cvoid}, ::Type{String})
    cstr = @ccall CFStringGetCStringPtr(p::Ptr{Cvoid}, UInt32(4)::UInt32)::Cstring
    if cstr != C_NULL
        return unsafe_string(cstr)
    end
    # Slow path: CFStringGetCStringPtr may return NULL for some encodings.
    len = @ccall CFStringGetLength(p::Ptr{Cvoid})::Int64
    buf = Vector{UInt8}(undef, len * 4 + 1)
    ok = GC.@preserve buf @ccall CFStringGetCString(
        p::Ptr{Cvoid}, pointer(buf)::Ptr{Cuchar}, Int64(length(buf))::Int64, UInt32(4)::UInt32
    )::Bool
    ok || return nothing
    return GC.@preserve buf unsafe_string(pointer(buf))
end

function _cf_to_julia(p::Ptr{Cvoid}, ::Type{Bool})
    return @ccall CFBooleanGetValue(p::Ptr{Cvoid})::Bool
end

# CFAbsoluteTime epoch: 2001-01-01T00:00:00 UTC
const _CF_EPOCH = DateTime(2001, 1, 1, 0, 0, 0)

function _cf_to_julia(p::Ptr{Cvoid}, ::Type{DateTime})
    abs_time = @ccall CFDateGetAbsoluteTime(p::Ptr{Cvoid})::Float64
    return _CF_EPOCH + Dates.Millisecond(round(Int64, abs_time * 1000))
end

function _cf_to_julia(p::Ptr{Cvoid}, ::Type{Vector{UInt8}})
    len       = @ccall CFDataGetLength(p::Ptr{Cvoid})::Int64
    bytes_ptr = @ccall CFDataGetBytePtr(p::Ptr{Cvoid})::Ptr{Cuchar}
    out = Vector{UInt8}(undef, Int(len))
    GC.@preserve out begin
        len > 0 && unsafe_copyto!(pointer(out), Ptr{UInt8}(bytes_ptr), Int(len))
    end
    return out
end

function _cf_to_julia(p::Ptr{Cvoid}, ::Type{Int})
    v = Ref{Int32}(0)
    @ccall CFNumberGetValue(p::Ptr{Cvoid}, Int32(3)::Int32, v::Ref{Int32})::Bool
    return Int(v[])
end

# Symbol reverse-lookup requires the valid-constants set since CF doesn't self-describe identity.
function _cf_to_julia(p::Ptr{Cvoid}, ::Type{Symbol}, constants)
    for sym in constants
        _sec(sym) == p && return sym
    end
    return nothing
end

function _cfdata_write_io(cfdata::Ptr{Cvoid}, io::IO)
    len       = @ccall CFDataGetLength(cfdata::Ptr{Cvoid})::Int64
    bytes_ptr = @ccall CFDataGetBytePtr(cfdata::Ptr{Cvoid})::Ptr{Cuchar}
    buf = Vector{UInt8}(undef, Int(len))
    try
        GC.@preserve buf begin
            len > 0 && unsafe_copyto!(pointer(buf), Ptr{UInt8}(bytes_ptr), Int(len))
        end
        write(io, buf)
    finally
        Base.securezero!(buf)
    end
end

# ── Generic CRUD implementations ───────────────────────────────────────────────
#
# These work for any AbstractKeychainItem that implements:
#   • Base.pairs(item)      — full query dict including kSecClass + keychain target
#   • _parse_item_result(attrs::Ptr{Cvoid}, fallback::T) — deserialize a CF dict back into T

function add_item!(item::AbstractKeychainItem, secret::Union{IO, AbstractVector{UInt8}, AbstractString})
    _with_secret_bytes(secret) do bytes
        _sec_item_add([pairs(item)..., :kSecValueData => bytes], keychain_target(item))
    end
    return nothing
end

function search_items(query::T) where T <: AbstractKeychainItem
    q = Pair{Symbol,Any}[pairs(query)...]
    push!(q, :kSecReturnAttributes => true)
    push!(q, :kSecMatchLimit       => :kSecMatchLimitAll)

    arr = _sec_item_copy_all(q, keychain_target(query))
    arr == C_NULL && return T[]
    try
        count = @ccall CFArrayGetCount(arr::Ptr{Cvoid})::Int64
        return [
            _parse_item_result(
                @ccall(CFArrayGetValueAtIndex(arr::Ptr{Cvoid}, Int64(i - 1)::Int64)::Ptr{Cvoid}),
                query,
            )
            for i in 1:count
        ]
    finally
        @ccall CFRelease(arr::Ptr{Cvoid})::Cvoid
    end
end

function copy_secret(
    item::AbstractKeychainItem;
    into::Union{Nothing, IO}                             = nothing,
    use_authentication_ui::Union{Nothing, Symbol}        = nothing,
    use_operation_prompt::Union{Nothing, AbstractString} = nothing,
)
    if use_authentication_ui !== nothing
        use_authentication_ui in _AUTH_UI_VALUES ||
            throw(KeychainOperationError("Unsupported kSecUseAuthenticationUI value: $use_authentication_ui"))
    end

    auto_created = into === nothing
    io = auto_created ? Base.SecretBuffer() : into

    query = Pair{Symbol,Any}[pairs(item)...]
    push!(query, :kSecReturnData  => true)
    push!(query, :kSecMatchLimit  => :kSecMatchLimitOne)
    use_authentication_ui !== nothing && push!(query, :kSecUseAuthenticationUI => use_authentication_ui)
    use_operation_prompt  !== nothing && push!(query, :kSecUseOperationPrompt  => use_operation_prompt)

    try
        result = _sec_item_copy_matching(query, keychain_target(item))
        try
            _cfdata_write_io(result, io)
        finally
            result != C_NULL && @ccall CFRelease(result::Ptr{Cvoid})::Cvoid
        end
    catch
        auto_created && Base.shred!(io)
        rethrow()
    end
    auto_created && seekstart(io)
    return io
end

function update_item!(
    query::AbstractKeychainItem,
    attributes::AbstractKeychainItem;
    secret::Union{Nothing, IO, AbstractVector{UInt8}, AbstractString} = nothing,
)
    update = filter(p -> p.first !== :kSecClass, pairs(attributes))
    if secret !== nothing
        _with_secret_bytes(secret) do bytes
            _sec_item_update(pairs(query), [update..., :kSecValueData => bytes], keychain_target(query))
        end
    else
        _sec_item_update(pairs(query), update, keychain_target(query))
    end
    return nothing
end

function delete_item!(item::AbstractKeychainItem)
    _sec_item_delete(pairs(item), keychain_target(item))
    return nothing
end

# ── Entitlement probe ──────────────────────────────────────────────────────────

"""
    probe_data_protection_entitlement() -> Bool

Returns `true` when the current process has the entitlements required to access
the Data Protection keychain, `false` otherwise.

This is determined by reading the process's own code-signing entitlements via
`SecTaskCreateFromSelf` / `SecTaskCopyValueForEntitlement` — no keychain
operation is performed. Per Apple's [Keychain Access Groups]
(https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps)
documentation, Data Protection keychain access requires at least one of:

- `keychain-access-groups` — a non-empty CFArrayRef of access-group strings.
- `com.apple.application-identifier` — present on sandboxed and properly
  signed macOS apps.
"""
function probe_data_protection_entitlement()::Bool
    task = @ccall SecTaskCreateFromSelf(C_NULL::Ptr{Cvoid})::Ptr{Cvoid}
    task == C_NULL && return false
    try
        # keychain-access-groups is a CFArrayRef; check it is also non-empty.
        # com.apple.application-identifier is a CFStringRef; presence is sufficient.
        for (key, check_nonempty) in (
                ("keychain-access-groups",          true),
                ("com.apple.application-identifier", false),
            )
            cfkey = @ccall CFStringCreateWithCString(
                C_NULL::Ptr{Cvoid}, key::Cstring, UInt32(4)::UInt32
            )::Ptr{Cvoid}
            cfkey == C_NULL && continue
            value = try
                @ccall SecTaskCopyValueForEntitlement(
                    task::Ptr{Cvoid}, cfkey::Ptr{Cvoid}, C_NULL::Ptr{Cvoid}
                )::Ptr{Cvoid}
            finally
                @ccall CFRelease(cfkey::Ptr{Cvoid})::Cvoid
            end
            value == C_NULL && continue
            if check_nonempty
                count = @ccall CFArrayGetCount(value::Ptr{Cvoid})::Int64
                @ccall CFRelease(value::Ptr{Cvoid})::Cvoid
                count > 0 && return true
            else
                @ccall CFRelease(value::Ptr{Cvoid})::Cvoid
                return true
            end
        end
        return false
    finally
        @ccall CFRelease(task::Ptr{Cvoid})::Cvoid
    end
end
