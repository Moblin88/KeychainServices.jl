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

"""
    AbstractKeychainItem

Abstract supertype for all keychain items. Concrete subtypes implement
`Base.pairs` to yield `(Symbol, Any)` attribute pairs that are marshalled into
Core Foundation dictionaries for use with the Security.framework SecItem API.
"""
abstract type AbstractKeychainItem end

"""
    KeychainItemResult{T}

Return value from [`copy_matching`](@ref). Carries the matched `item` (populated
from keychain attributes when `return_attributes=true`), an optional `secret`
(an `IO` object positioned at the start of the secret bytes when `return_data=true`),
and optional `created_at` / `updated_at` timestamps.

When no `secret_output` is passed to `copy_matching`, `secret` is a
`Base.SecretBuffer` already rewound to position 0 and ready to read.
"""
Base.@kwdef struct KeychainItemResult{T<:AbstractKeychainItem}
    item::T
    secret::Union{Nothing, IO}           = nothing
    created_at::Union{Nothing, DateTime} = nothing
    updated_at::Union{Nothing, DateTime} = nothing
end

# ── Error types ────────────────────────────────────────────────────────────────

"""
    KeychainServicesError

Abstract supertype for all errors thrown by KeychainServices.jl.
"""
abstract type KeychainServicesError <: Exception end

"""
    KeychainOperationError(message)

Thrown when a Security.framework SecItem call returns an unexpected error code.
`message` includes the operation name and the OSStatus value.
"""
struct KeychainOperationError    <: KeychainServicesError; message::String; end

"""
    UnsupportedPlatformError(platform, message)

Thrown when a KeychainServices function is called on a non-Apple platform.
"""
struct UnsupportedPlatformError  <: KeychainServicesError; platform::Symbol; message::String; end

"""
    KeychainItemNotFoundError(message)

Thrown by [`copy_matching`](@ref) or [`delete_item!`](@ref) when no keychain
item matches the query.
"""
struct KeychainItemNotFoundError <: KeychainServicesError; message::String; end

"""
    KeychainPermissionError(message)

Thrown when a SecItem operation fails due to a missing entitlement or access
denial (e.g., `errSecMissingEntitlement`, `errSecAuthFailed`).
"""
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
    add_item!(item::AbstractKeychainItem, secret)

Store a new keychain item. `secret` may be an `IO` (read from current position),
an `AbstractVector{UInt8}`, or an `AbstractString`. Bytes are used for the keychain
write; any temporary copy is zeroed. The original `secret` is not modified — callers
retain ownership.
"""
function add_item! end

"""
    copy_matching(item::AbstractKeychainItem; return_data=true, return_attributes=false,
                  secret_output::Union{Nothing,IO}=nothing,
                  use_authentication_ui=nothing, use_operation_prompt=nothing) -> KeychainItemResult

Find a keychain item by matching the non-`nothing` fields of `item`.

- `return_data=true` — include the secret in the result's `secret` field.
- `return_attributes=true` — populate the result `item` from the keychain metadata.
- `secret_output` — an `IO` to write the secret bytes into. When `nothing` (the
  default), a `Base.SecretBuffer` is created automatically and rewound to position 0
  before being returned in `KeychainItemResult.secret`.

On the Data Protection keychain, `use_authentication_ui` (a `kSecUseAuthenticationUI*`
symbol) and `use_operation_prompt` (a `String`) control how the system presents
authentication UI.
"""
function copy_matching end

"""
    update_item!(query::AbstractKeychainItem, attributes::AbstractKeychainItem; secret=nothing)

Update an existing keychain item. `query` selects the item; non-`nothing` fields of
`attributes` are applied as changes. Pass `secret` (`IO`, `AbstractVector{UInt8}`, or
`AbstractString`) to rotate the password — bytes are used and any temporary copy is zeroed.
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
the Data Protection keychain, `false` otherwise.

Reads the process's own code-signing entitlements via `SecTaskCreateFromSelf` /
`SecTaskCopyValueForEntitlement` — no keychain operation is performed. Returns
`true` if `keychain-access-groups` (non-empty) or `com.apple.application-identifier`
is present in the process entitlements.
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

    add_item!(::AbstractKeychainItem, ::Union{IO, AbstractVector{UInt8}, AbstractString}) = _unsupported()
    copy_matching(::AbstractKeychainItem; kwargs...)                   = _unsupported()
    update_item!(::AbstractKeychainItem, ::AbstractKeychainItem; kwargs...) = _unsupported()
    delete_item!(::AbstractKeychainItem)                               = _unsupported()
    probe_data_protection_entitlement()                                = _unsupported()
end

end # module