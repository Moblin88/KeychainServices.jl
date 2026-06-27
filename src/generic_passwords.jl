const _ACCESSIBLE_VALUES = (
    :kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
    :kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    :kSecAttrAccessibleWhenUnlocked,
    :kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    :kSecAttrAccessibleAfterFirstUnlock,
    :kSecAttrAccessibleAlwaysThisDeviceOnly,
    :kSecAttrAccessibleAlways,
)

"""
    GenericPasswordItem(; service, account, label, synchronizable, accessible,
                          access_group, description, comment, is_invisible,
                          is_negative, generic_data, access_control, keychain,
                          created_at, updated_at)

Julia representation of a `kSecClassGenericPassword` keychain item.

Fields set to `nothing` are omitted from Security.framework query dictionaries.
`created_at` and `updated_at` are populated by [`search_items`](@ref) and are
ignored when the item is used as a query or mutation target.

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
    created_at::Union{Nothing, DateTime}         = nothing
    updated_at::Union{Nothing, DateTime}         = nothing
end

KeychainServices.keychain_target(item::GenericPasswordItem) = item.keychain

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

function _parse_item_result(attrs::Ptr{Cvoid}, fallback::GenericPasswordItem)
    coalesce(a, b) = a !== nothing ? a : b

    return GenericPasswordItem(
        service        = coalesce(_cf_dict_get(attrs, :kSecAttrService,        String),                          fallback.service),
        account        = coalesce(_cf_dict_get(attrs, :kSecAttrAccount,        String),                          fallback.account),
        label          = coalesce(_cf_dict_get(attrs, :kSecAttrLabel,          String),                          fallback.label),
        synchronizable = coalesce(_cf_dict_get(attrs, :kSecAttrSynchronizable, Bool),                            fallback.synchronizable),
        accessible     = coalesce(_cf_dict_get(attrs, :kSecAttrAccessible,     Symbol, _ACCESSIBLE_VALUES),      fallback.accessible),
        access_group   = coalesce(_cf_dict_get(attrs, :kSecAttrAccessGroup,    String),                          fallback.access_group),
        description    = coalesce(_cf_dict_get(attrs, :kSecAttrDescription,    String),                          fallback.description),
        comment        = coalesce(_cf_dict_get(attrs, :kSecAttrComment,        String),                          fallback.comment),
        is_invisible   = coalesce(_cf_dict_get(attrs, :kSecAttrIsInvisible,    Bool),                            fallback.is_invisible),
        is_negative    = coalesce(_cf_dict_get(attrs, :kSecAttrIsNegative,     Bool),                            fallback.is_negative),
        generic_data   = coalesce(_cf_dict_get(attrs, :kSecAttrGeneric,        Vector{UInt8}),                   fallback.generic_data),
        access_control = fallback.access_control,
        keychain       = fallback.keychain,
        created_at     = _cf_dict_get(attrs, :kSecAttrCreationDate,     DateTime),
        updated_at     = _cf_dict_get(attrs, :kSecAttrModificationDate, DateTime),
    )
end

end # @static if Sys.isapple()