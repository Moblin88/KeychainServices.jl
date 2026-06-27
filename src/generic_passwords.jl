const _ACCESSIBLE_VALUES = (
    :kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
    :kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    :kSecAttrAccessibleWhenUnlocked,
    :kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    :kSecAttrAccessibleAfterFirstUnlock,
    :kSecAttrAccessibleAlwaysThisDeviceOnly,
    :kSecAttrAccessibleAlways,
)

const _AUTH_UI_VALUES = (
    :kSecUseAuthenticationUIAllow,
    :kSecUseAuthenticationUIFail,
    :kSecUseAuthenticationUISkip,
)

"""
    GenericPasswordItem(; service, account, label, synchronizable, accessible,
                          access_group, description, comment, is_invisible,
                          is_negative, generic_data, access_control, keychain)

Julia representation of a `kSecClassGenericPassword` keychain item.

Fields set to `nothing` are omitted from Security.framework query dictionaries.

The `keychain` field controls the keychain backend:
- [`LoginKeychain()`](@ref) *(default)* — user's login keychain (macOS system default)
- [`DataProtectionKeychain()`](@ref) — modern iOS-style Data Protection keychain
- [`FileKeychain(path)`](@ref) — specific legacy keychain file

Access-control policies for the Data Protection keychain can be expressed with an
[`AccessControlItem`](@ref) in `access_control`. When `access_control` is set, it
takes precedence over `accessible`.

## Examples

Basic item:
```julia
item = GenericPasswordItem(service="com.example.app", account="alice")
```

iCloud-synced item:
```julia
item = GenericPasswordItem(
    service="com.example.app",
    account="alice",
    synchronizable=true,
    accessible=:kSecAttrAccessibleWhenUnlocked,
)
```

Biometry-protected item (Data Protection keychain):
```julia
ctrl = AccessControlItem(
    :kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
    AccessControlFlags.BiometryAny | AccessControlFlags.DevicePasscode,
)
item = GenericPasswordItem(service="com.example.app", account="alice", access_control=ctrl)
```

Legacy login keychain:
```julia
item = GenericPasswordItem(service="com.example.app", account="alice", keychain=LoginKeychain())
```
"""
Base.@kwdef struct GenericPasswordItem <: AbstractKeychainItem
    service::Union{Nothing, String}              = nothing
    account::Union{Nothing, String}              = nothing
    label::Union{Nothing, String}                = nothing
    synchronizable::Union{Nothing, Bool}         = nothing
    accessible::Union{Nothing, Symbol}           = nothing
    access_group::Union{Nothing, String}         = nothing
    description::Union{Nothing, String}          = nothing
    comment::Union{Nothing, String}              = nothing
    is_invisible::Union{Nothing, Bool}           = nothing
    is_negative::Union{Nothing, Bool}            = nothing
    generic_data::Union{Nothing, Vector{UInt8}}  = nothing
    access_control::Union{Nothing, AccessControlItem} = nothing
    keychain::KeychainTarget                     = LoginKeychain()
end

_is_this_device_only(accessible::Symbol) = endswith(String(accessible), "ThisDeviceOnly")

function _validate_generic_password_item(item::GenericPasswordItem)
    if item.accessible !== nothing && item.access_control === nothing
        item.accessible in _ACCESSIBLE_VALUES ||
            throw(KeychainOperationError("Unsupported kSecAttrAccessible value: $(item.accessible)"))
        if item.synchronizable === true && _is_this_device_only(item.accessible)
            throw(KeychainOperationError(
                "`synchronizable=true` cannot be combined with `kSecAttrAccessible*ThisDeviceOnly` values"
            ))
        end
    end
    if item.access_control !== nothing
        item.access_control.accessible in _ACCESSIBLE_VALUES ||
            throw(KeychainOperationError(
                "Unsupported kSecAttrAccessible value in AccessControlItem: $(item.access_control.accessible)"
            ))
    end
end

"""
    Base.pairs(item::GenericPasswordItem)

Returns the Security.framework key-value pairs for `item`, suitable for passing to
the low-level `_cf_dict` builder. Includes `kSecClass`, all non-`nothing` attributes,
and the keychain-target entries. Used by all CRUD operations.
"""
function Base.pairs(item::GenericPasswordItem)
    _validate_generic_password_item(item)
    attrs = Pair{Symbol,Any}[:kSecClass => :kSecClassGenericPassword]

    item.service      !== nothing && push!(attrs, :kSecAttrService       => item.service)
    item.account      !== nothing && push!(attrs, :kSecAttrAccount       => item.account)
    item.label        !== nothing && push!(attrs, :kSecAttrLabel         => item.label)
    item.synchronizable !== nothing && push!(attrs, :kSecAttrSynchronizable => item.synchronizable)
    item.access_group !== nothing && push!(attrs, :kSecAttrAccessGroup   => item.access_group)
    item.description  !== nothing && push!(attrs, :kSecAttrDescription   => item.description)
    item.comment      !== nothing && push!(attrs, :kSecAttrComment       => item.comment)
    item.is_invisible !== nothing && push!(attrs, :kSecAttrIsInvisible   => item.is_invisible)
    item.is_negative  !== nothing && push!(attrs, :kSecAttrIsNegative    => item.is_negative)
    item.generic_data !== nothing && push!(attrs, :kSecAttrGeneric       => item.generic_data)

    if item.access_control !== nothing
        push!(attrs, :kSecAttrAccessControl => item.access_control)
    elseif item.accessible !== nothing
        push!(attrs, :kSecAttrAccessible => item.accessible)
    end

    append!(attrs, _keychain_target_pairs(item.keychain))
    return attrs
end

# Returns attribute pairs suitable for the `attributes` argument of SecItemUpdate —
# no kSecClass, no keychain-target keys, only the explicitly-set mutable fields.
function _update_pairs(item::GenericPasswordItem)
    attrs = Pair{Symbol,Any}[]

    item.service      !== nothing && push!(attrs, :kSecAttrService       => item.service)
    item.account      !== nothing && push!(attrs, :kSecAttrAccount       => item.account)
    item.label        !== nothing && push!(attrs, :kSecAttrLabel         => item.label)
    item.synchronizable !== nothing && push!(attrs, :kSecAttrSynchronizable => item.synchronizable)
    item.access_group !== nothing && push!(attrs, :kSecAttrAccessGroup   => item.access_group)
    item.description  !== nothing && push!(attrs, :kSecAttrDescription   => item.description)
    item.comment      !== nothing && push!(attrs, :kSecAttrComment       => item.comment)
    item.is_invisible !== nothing && push!(attrs, :kSecAttrIsInvisible   => item.is_invisible)
    item.is_negative  !== nothing && push!(attrs, :kSecAttrIsNegative    => item.is_negative)
    item.generic_data !== nothing && push!(attrs, :kSecAttrGeneric       => item.generic_data)

    if item.access_control !== nothing
        push!(attrs, :kSecAttrAccessControl => item.access_control)
    elseif item.accessible !== nothing
        push!(attrs, :kSecAttrAccessible => item.accessible)
    end

    return attrs
end

@static if Sys.isapple()

function _parse_generic_password_result(attrs::Ptr{Cvoid}, fallback::GenericPasswordItem)
    get_str(key)   = let p = _cf_dict_get(attrs, key); p == C_NULL ? nothing : _cfstring_to_string(p) end
    get_bool(key)  = let p = _cf_dict_get(attrs, key); p == C_NULL ? nothing : _cfboolean_to_bool(p) end
    get_bytes(key) = let p = _cf_dict_get(attrs, key); p == C_NULL ? nothing : _cfdata_to_bytes(p) end
    get_date(key)  = let p = _cf_dict_get(attrs, key); p == C_NULL ? nothing : _cfdate_to_datetime(p) end
    get_const(key, syms) = let p = _cf_dict_get(attrs, key)
        p == C_NULL ? nothing : _cf_constant_to_symbol(p, syms)
    end

    # Use fallback for fields not present in the result dict.
    coalesce(a, b) = a !== nothing ? a : b

    item = GenericPasswordItem(
        service        = coalesce(get_str(:kSecAttrService),                   fallback.service),
        account        = coalesce(get_str(:kSecAttrAccount),                   fallback.account),
        label          = coalesce(get_str(:kSecAttrLabel),                     fallback.label),
        synchronizable = coalesce(get_bool(:kSecAttrSynchronizable),           fallback.synchronizable),
        accessible     = coalesce(get_const(:kSecAttrAccessible, _ACCESSIBLE_VALUES), fallback.accessible),
        access_group   = coalesce(get_str(:kSecAttrAccessGroup),               fallback.access_group),
        description    = coalesce(get_str(:kSecAttrDescription),               fallback.description),
        comment        = coalesce(get_str(:kSecAttrComment),                   fallback.comment),
        is_invisible   = coalesce(get_bool(:kSecAttrIsInvisible),              fallback.is_invisible),
        is_negative    = coalesce(get_bool(:kSecAttrIsNegative),               fallback.is_negative),
        generic_data   = coalesce(get_bytes(:kSecAttrGeneric),                 fallback.generic_data),
        access_control = fallback.access_control,
        keychain       = fallback.keychain,
    )

    return item, get_date(:kSecAttrCreationDate), get_date(:kSecAttrModificationDate)
end

function _parse_copy_matching_result(
    query_item::GenericPasswordItem,
    return_data::Bool,
    return_attributes::Bool,
    result::Ptr{Cvoid},
)
    if return_attributes
        item, created_at, updated_at = _parse_generic_password_result(result, query_item)
        secret = if return_data
            data_ptr = _cf_dict_get(result, :kSecValueData)
            data_ptr == C_NULL && throw(KeychainOperationError("kSecReturnData=true but no kSecValueData in result"))
            _cfdata_to_secretbuffer(data_ptr)
        else
            nothing
        end
        return KeychainItemResult(item=item, secret=secret, created_at=created_at, updated_at=updated_at)
    elseif return_data
        return KeychainItemResult(item=query_item, secret=_cfdata_to_secretbuffer(result))
    end
    return KeychainItemResult(item=query_item)
end

function add_item!(item::GenericPasswordItem, secret::IO)
    _with_secret_bytes(secret) do bytes
        _sec_item_add([pairs(item)..., :kSecValueData => bytes])
    end
    return nothing
end

function copy_matching(
    item::GenericPasswordItem;
    return_data::Bool           = true,
    return_attributes::Bool     = false,
    use_authentication_ui::Union{Nothing, Symbol}       = nothing,
    use_operation_prompt::Union{Nothing, AbstractString} = nothing,
)
    if use_authentication_ui !== nothing
        use_authentication_ui in _AUTH_UI_VALUES ||
            throw(KeychainOperationError("Unsupported kSecUseAuthenticationUI value: $use_authentication_ui"))
    end

    query = Pair{Symbol,Any}[pairs(item)...]
    push!(query, :kSecReturnData       => return_data)
    push!(query, :kSecReturnAttributes => return_attributes)
    push!(query, :kSecMatchLimit       => :kSecMatchLimitOne)
    use_authentication_ui !== nothing && push!(query, :kSecUseAuthenticationUI => use_authentication_ui)
    use_operation_prompt  !== nothing && push!(query, :kSecUseOperationPrompt  => use_operation_prompt)

    result = _sec_item_copy_matching(query)
    try
        return _parse_copy_matching_result(item, return_data, return_attributes, result)
    finally
        result != C_NULL && @ccall CFRelease(result::Ptr{Cvoid})::Cvoid
    end
end

function update_item!(
    query::GenericPasswordItem,
    attributes::GenericPasswordItem;
    secret::Union{Nothing, IO} = nothing,
)
    update = _update_pairs(attributes)
    if secret !== nothing
        _with_secret_bytes(secret) do bytes
            _sec_item_update(pairs(query), [update..., :kSecValueData => bytes])
        end
    else
        _sec_item_update(pairs(query), update)
    end
    return nothing
end

function delete_item!(item::GenericPasswordItem)
    _sec_item_delete(pairs(item))
    return nothing
end

end # @static if Sys.isapple()