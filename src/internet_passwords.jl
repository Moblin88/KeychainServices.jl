const _INTERNET_PROTOCOL_VALUES = (
    :kSecAttrProtocolFTP,
    :kSecAttrProtocolFTPAccount,
    :kSecAttrProtocolHTTP,
    :kSecAttrProtocolIRC,
    :kSecAttrProtocolNNTP,
    :kSecAttrProtocolPOP3,
    :kSecAttrProtocolSMTP,
    :kSecAttrProtocolSOCKS,
    :kSecAttrProtocolIMAP,
    :kSecAttrProtocolLDAP,
    :kSecAttrProtocolAppleTalk,
    :kSecAttrProtocolAFP,
    :kSecAttrProtocolTelnet,
    :kSecAttrProtocolSSH,
    :kSecAttrProtocolFTPS,
    :kSecAttrProtocolHTTPS,
    :kSecAttrProtocolHTTPProxy,
    :kSecAttrProtocolHTTPSProxy,
    :kSecAttrProtocolFTPProxy,
    :kSecAttrProtocolSMB,
    :kSecAttrProtocolRTSP,
    :kSecAttrProtocolRTSPProxy,
    :kSecAttrProtocolDAAP,
    :kSecAttrProtocolEPPC,
    :kSecAttrProtocolIPP,
    :kSecAttrProtocolNNTPS,
    :kSecAttrProtocolLDAPS,
    :kSecAttrProtocolTelnetS,
    :kSecAttrProtocolIMAPS,
    :kSecAttrProtocolIRCS,
    :kSecAttrProtocolPOP3S,
)

const _INTERNET_AUTH_TYPE_VALUES = (
    :kSecAttrAuthenticationTypeNTLM,
    :kSecAttrAuthenticationTypeMSN,
    :kSecAttrAuthenticationTypeDPA,
    :kSecAttrAuthenticationTypeRPA,
    :kSecAttrAuthenticationTypeHTTPBasic,
    :kSecAttrAuthenticationTypeHTTPDigest,
    :kSecAttrAuthenticationTypeHTMLForm,
    :kSecAttrAuthenticationTypeDefault,
)

"""
    InternetPasswordItem(; server, account, path, port, protocol, authentication_type,
                           security_domain, label, synchronizable, accessible,
                           access_group, description, comment, is_invisible,
                           is_negative, access_control, keychain,
                           created_at, updated_at)

Julia representation of a `kSecClassInternetPassword` keychain item.

Fields set to `nothing` are omitted from Security.framework query dictionaries.
`created_at` and `updated_at` are populated by [`search_items`](@ref) and are
ignored when the item is used as a query or mutation target.

The `keychain` field controls the keychain backend:
- [`LoginKeychain()`](@ref) *(default)* — user's login keychain
- [`DataProtectionKeychain()`](@ref) — modern iOS-style Data Protection keychain
- [`FileKeychain(path)`](@ref) — specific legacy keychain file

## Examples

Basic item:
```julia
item = InternetPasswordItem(server="api.example.com", account="alice")
```

Full item with protocol and port:
```julia
item = InternetPasswordItem(
    server   = "api.example.com",
    account  = "alice",
    protocol = :kSecAttrProtocolHTTPS,
    port     = 443,
    path     = "/v1",
)
```

iCloud-synced item:
```julia
item = InternetPasswordItem(
    server        = "api.example.com",
    account       = "alice",
    synchronizable = true,
    accessible    = :kSecAttrAccessibleWhenUnlocked,
)
```
"""
Base.@kwdef struct InternetPasswordItem <: AbstractKeychainItem
    server::Union{Nothing, String}                    = nothing
    account::Union{Nothing, String}                   = nothing
    path::Union{Nothing, String}                      = nothing
    port::Union{Nothing, Int}                         = nothing
    protocol::Union{Nothing, Symbol}                  = nothing
    authentication_type::Union{Nothing, Symbol}       = nothing
    security_domain::Union{Nothing, String}           = nothing
    label::Union{Nothing, String}                     = nothing
    synchronizable::Union{Nothing, Bool}              = nothing
    accessible::Union{Nothing, Symbol}                = nothing
    access_group::Union{Nothing, String}              = nothing
    description::Union{Nothing, String}               = nothing
    comment::Union{Nothing, String}                   = nothing
    is_invisible::Union{Nothing, Bool}                = nothing
    is_negative::Union{Nothing, Bool}                 = nothing
    access_control::Union{Nothing, AccessControlItem} = nothing
    keychain::KeychainTarget                          = LoginKeychain()
    created_at::Union{Nothing, DateTime}              = nothing
    updated_at::Union{Nothing, DateTime}              = nothing
end

KeychainServices.keychain_target(item::InternetPasswordItem) = item.keychain

function _validate_internet_password_item(item::InternetPasswordItem)
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
    Base.pairs(item::InternetPasswordItem)

Returns the Security.framework key-value pairs for `item`, suitable for passing to
the low-level `_cf_dict` builder. Includes `kSecClass`, all non-`nothing` attributes,
and the keychain-target entries.
"""
function Base.pairs(item::InternetPasswordItem)
    _validate_internet_password_item(item)
    attrs = Pair{Symbol,Any}[:kSecClass => :kSecClassInternetPassword]

    item.server              !== nothing && push!(attrs, :kSecAttrServer             => item.server)
    item.account             !== nothing && push!(attrs, :kSecAttrAccount            => item.account)
    item.path                !== nothing && push!(attrs, :kSecAttrPath               => item.path)
    item.port                !== nothing && push!(attrs, :kSecAttrPort               => item.port)
    item.protocol            !== nothing && push!(attrs, :kSecAttrProtocol           => item.protocol)
    item.authentication_type !== nothing && push!(attrs, :kSecAttrAuthenticationType => item.authentication_type)
    item.security_domain     !== nothing && push!(attrs, :kSecAttrSecurityDomain     => item.security_domain)
    item.label               !== nothing && push!(attrs, :kSecAttrLabel              => item.label)
    item.synchronizable      !== nothing && push!(attrs, :kSecAttrSynchronizable     => item.synchronizable)
    item.access_group        !== nothing && push!(attrs, :kSecAttrAccessGroup        => item.access_group)
    item.description         !== nothing && push!(attrs, :kSecAttrDescription        => item.description)
    item.comment             !== nothing && push!(attrs, :kSecAttrComment            => item.comment)
    item.is_invisible        !== nothing && push!(attrs, :kSecAttrIsInvisible        => item.is_invisible)
    item.is_negative         !== nothing && push!(attrs, :kSecAttrIsNegative         => item.is_negative)

    if item.access_control !== nothing
        push!(attrs, :kSecAttrAccessControl => item.access_control)
    elseif item.accessible !== nothing
        push!(attrs, :kSecAttrAccessible => item.accessible)
    end

    return attrs
end


@static if Sys.isapple()

function _parse_item_result(attrs::Ptr{Cvoid}, fallback::InternetPasswordItem)
    coalesce(a, b) = a !== nothing ? a : b

    return InternetPasswordItem(
        server              = coalesce(_cf_dict_get(attrs, :kSecAttrServer,             String),                                    fallback.server),
        account             = coalesce(_cf_dict_get(attrs, :kSecAttrAccount,            String),                                    fallback.account),
        path                = coalesce(_cf_dict_get(attrs, :kSecAttrPath,               String),                                    fallback.path),
        port                = coalesce(_cf_dict_get(attrs, :kSecAttrPort,               Int),                                       fallback.port),
        protocol            = coalesce(_cf_dict_get(attrs, :kSecAttrProtocol,           Symbol, _INTERNET_PROTOCOL_VALUES),         fallback.protocol),
        authentication_type = coalesce(_cf_dict_get(attrs, :kSecAttrAuthenticationType, Symbol, _INTERNET_AUTH_TYPE_VALUES),        fallback.authentication_type),
        security_domain     = coalesce(_cf_dict_get(attrs, :kSecAttrSecurityDomain,     String),                                    fallback.security_domain),
        label               = coalesce(_cf_dict_get(attrs, :kSecAttrLabel,              String),                                    fallback.label),
        synchronizable      = coalesce(_cf_dict_get(attrs, :kSecAttrSynchronizable,     Bool),                                      fallback.synchronizable),
        accessible          = coalesce(_cf_dict_get(attrs, :kSecAttrAccessible,         Symbol, _ACCESSIBLE_VALUES),                fallback.accessible),
        access_group        = coalesce(_cf_dict_get(attrs, :kSecAttrAccessGroup,        String),                                    fallback.access_group),
        description         = coalesce(_cf_dict_get(attrs, :kSecAttrDescription,        String),                                    fallback.description),
        comment             = coalesce(_cf_dict_get(attrs, :kSecAttrComment,            String),                                    fallback.comment),
        is_invisible        = coalesce(_cf_dict_get(attrs, :kSecAttrIsInvisible,        Bool),                                      fallback.is_invisible),
        is_negative         = coalesce(_cf_dict_get(attrs, :kSecAttrIsNegative,         Bool),                                      fallback.is_negative),
        access_control      = fallback.access_control,
        keychain            = fallback.keychain,
        created_at          = _cf_dict_get(attrs, :kSecAttrCreationDate,     DateTime),
        updated_at          = _cf_dict_get(attrs, :kSecAttrModificationDate, DateTime),
    )
end

end # @static if Sys.isapple()
