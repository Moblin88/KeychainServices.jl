module KeychainServices

using Dates

export AbstractKeychainItem,
       GenericPasswordItem,
       KeychainItemResult,
       KeychainTarget,
       DataProtectionKeychain,
       LoginKeychain,
       FileKeychain,
       AccessControlItem,
       AccessControlFlags,
       KeychainServicesError,
       KeychainOperationError,
       UnsupportedPlatformError,
       KeychainItemNotFoundError,
       KeychainPermissionError,
       add_item!,
       copy_matching,
       update_item!,
       delete_item!,
       probe_data_protection_entitlement

# ── Core abstractions ──────────────────────────────────────────────────────────

abstract type AbstractKeychainItem end

"""
    KeychainItemResult{T}

Return value from [`copy_matching`](@ref). Carries the matched `item` (populated
from keychain attributes when `return_attributes=true`), an optional `secret`
(`Base.SecretBuffer` when `return_data=true`), and optional `created_at` /
`updated_at` timestamps.
"""
Base.@kwdef struct KeychainItemResult{T<:AbstractKeychainItem}
    item::T
    secret::Union{Nothing, Base.SecretBuffer} = nothing
    created_at::Union{Nothing, DateTime}      = nothing
    updated_at::Union{Nothing, DateTime}      = nothing
end

# ── Error types ────────────────────────────────────────────────────────────────

abstract type KeychainServicesError <: Exception end
struct KeychainOperationError    <: KeychainServicesError; message::String; end
struct UnsupportedPlatformError  <: KeychainServicesError; platform::Symbol; message::String; end
struct KeychainItemNotFoundError <: KeychainServicesError; message::String; end
struct KeychainPermissionError   <: KeychainServicesError; message::String; end

Base.showerror(io::IO, e::KeychainOperationError)    = print(io, e.message)
Base.showerror(io::IO, e::UnsupportedPlatformError)  = print(io, "Unsupported platform $(e.platform): $(e.message)")
Base.showerror(io::IO, e::KeychainItemNotFoundError) = print(io, e.message)
Base.showerror(io::IO, e::KeychainPermissionError)   = print(io, e.message)

# ── Pure-Julia types (platform-independent) ────────────────────────────────────

include("keychain_targets.jl")
include("access_control.jl")
include("generic_passwords.jl")

# ── Public API stubs (for documentation and non-Apple dispatch) ────────────────

"""
    add_item!(item::AbstractKeychainItem, secret::Base.SecretBuffer)

Store a new keychain item. `secret` is the password data; it must be a
`Base.SecretBuffer` so that callers retain explicit control over when the bytes
are shredded from memory.
"""
function add_item! end

"""
    copy_matching(item::AbstractKeychainItem; return_data=true, return_attributes=false,
                  use_authentication_ui=nothing, use_operation_prompt=nothing) -> KeychainItemResult

Find a keychain item by matching the non-`nothing` fields of `item`.

- `return_data=true` — include the secret in the result's `secret` field.
- `return_attributes=true` — populate the result `item` from the keychain metadata.

On the Data Protection keychain, `use_authentication_ui` (a `kSecUseAuthenticationUI*`
symbol) and `use_operation_prompt` (a `String`) control how the system presents
authentication UI.
"""
function copy_matching end

"""
    update_item!(query::AbstractKeychainItem, attributes::AbstractKeychainItem; secret=nothing)

Update an existing keychain item. `query` selects the item; non-`nothing` fields of
`attributes` are applied as changes. Pass `secret` to rotate the password.
"""
function update_item! end

"""
    delete_item!(item::AbstractKeychainItem)

Delete the keychain item identified by the non-`nothing` fields of `item`.
"""
function delete_item! end

"""
    probe_data_protection_entitlement() -> Bool

Returns `true` when the current process has the entitlements required to access
the Data Protection keychain, `false` otherwise (i.e., when `SecItemCopyMatching`
returns `errSecMissingEntitlement`).
"""
function probe_data_protection_entitlement end

# ── Platform implementations ───────────────────────────────────────────────────

@static if Sys.isapple()
    include("cf_interop.jl")
else
    _platform() = Symbol(lowercase(String(Sys.KERNEL)))
    _unsupported() = throw(UnsupportedPlatformError(
        _platform(), "Keychain Services is only available on Apple platforms"
    ))

    add_item!(::AbstractKeychainItem, ::Base.SecretBuffer)             = _unsupported()
    copy_matching(::AbstractKeychainItem; kwargs...)                   = _unsupported()
    update_item!(::AbstractKeychainItem, ::AbstractKeychainItem; kwargs...) = _unsupported()
    delete_item!(::AbstractKeychainItem)                               = _unsupported()
    probe_data_protection_entitlement()                                = _unsupported()
end

end # module