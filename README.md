# KeychainServices

[![Build Status](https://github.com/Moblin88/KeychainServices.jl/actions/workflows/CI.yml/badge.svg?branch=main)](https://github.com/Moblin88/KeychainServices.jl/actions/workflows/CI.yml?query=branch%3Amain)
[![Coverage](https://codecov.io/gh/Moblin88/KeychainServices.jl/branch/main/graph/badge.svg)](https://codecov.io/gh/Moblin88/KeychainServices.jl)
[![Docs (stable)](https://img.shields.io/badge/docs-stable-blue.svg)](https://Moblin88.github.io/KeychainServices.jl/stable/)
[![Docs (dev)](https://img.shields.io/badge/docs-dev-blue.svg)](https://Moblin88.github.io/KeychainServices.jl/dev/)

KeychainServices.jl is a direct Julia wrapper over Apple's Keychain Services API for macOS.

The package calls Security.framework natively through Julia `@ccall` bindings. It does not shell out to the `security` command-line tool.

Supported item classes:

- `kSecClassGenericPassword` — generic passwords ([`GenericPasswordItem`](@ref))
- `kSecClassInternetPassword` — internet / URL-keyed passwords ([`InternetPasswordItem`](@ref))

## Platform Support

- macOS: supported
- Other platforms: loading succeeds, but Keychain operations raise `UnsupportedPlatformError`

You can check if the current machine is Apple/macOS with Julia built-ins:

```julia
is_apple = Sys.isapple()
```

## API

The same CRUD operations work for both item classes. Fields left as `nothing` are omitted from the underlying Security.framework query dictionary.

Secrets may be passed as a `Base.SecretBuffer` (or any `IO`), an `AbstractVector{UInt8}`, or an `AbstractString`. `copy_secret` returns a `Base.SecretBuffer` (seekstarted, ready to read) by default, or writes into a caller-supplied `IO` via the `into` keyword.

### Generic passwords

```julia
using KeychainServices

item = GenericPasswordItem(service="com.example.app", account="alice")

# Prompt the user interactively — no secret ever appears in source code
Base.shred!(Base.getpass("Enter password")) do secret
    add_item!(item, secret)
end

# Or construct the SecretBuffer directly when the value is already in memory
Base.shred!(Base.SecretBuffer("s3cr3t")) do secret
    add_item!(item, secret)
end

Base.shred!(copy_secret(item)) do password   # Base.SecretBuffer, seekstarted and ready to read
    # use password here
end

results = search_items(item)  # Vector{GenericPasswordItem} with metadata + timestamps
label   = results[1].label

Base.shred!(Base.getpass("Enter new password")) do rotated
    update_item!(item, GenericPasswordItem(label="Primary login"), rotated)
end

delete_item!(item)
```

Additional supported generic-password attributes:

- `accessible` (for example `:kSecAttrAccessibleWhenUnlocked`)
- `access_group`
- `description`
- `comment`
- `is_invisible`
- `is_negative`
- `generic_data` (`Vector{UInt8}`)
- `access_control` (`AccessControlItem`, for hardware-backed / biometry-protected items — requires a signed app bundle, see below)

### Internet passwords

```julia
using KeychainServices

item = InternetPasswordItem(server="api.example.com", account="alice")

# Prompt the user interactively — no secret ever appears in source code
Base.shred!(Base.getpass("Enter password")) do secret
    add_item!(item, secret)
end

# Or construct the SecretBuffer directly when the value is already in memory
Base.shred!(Base.SecretBuffer("s3cr3t")) do secret
    add_item!(item, secret)
end

Base.shred!(copy_secret(item)) do password   # Base.SecretBuffer, seekstarted and ready to read
    # use password here
end

results = search_items(item)  # Vector{InternetPasswordItem} with metadata + timestamps

Base.shred!(Base.getpass("Enter new password")) do rotated
    update_item!(item, InternetPasswordItem(label="Primary API key"), rotated)
end

delete_item!(item)
```

Additional supported internet-password attributes:

- `path` (URL path, e.g. `"/api/v1"`)
- `port` (`Int`)
- `protocol` (e.g. `:kSecAttrProtocolHTTPS`)
- `authentication_type` (e.g. `:kSecAttrAuthenticationTypeHTTPBasic`)
- `security_domain`
- `accessible` (for example `:kSecAttrAccessibleWhenUnlocked`)
- `access_group`
- `description`
- `comment`
- `is_invisible`
- `is_negative`
- `access_control` (`AccessControlItem`, requires a signed app bundle)
- `synchronizable`

> **Note:** `DataProtectionKeychain()` and `AccessControlItem` require the process to be
> code-signed with the `keychain-access-groups` entitlement. The standard `julia` host is
> unsigned, so using these from the REPL, scripts, or CI raises `KeychainPermissionError`.
> Use `LoginKeychain()` (the default) for interactive and scripting contexts. See the
> [docs](https://Moblin88.github.io/KeychainServices.jl/dev/keychain-types/) for the full
> signed-app workflow.

Query-time use restrictions for `copy_secret`:

- `use_authentication_ui` (`:kSecUseAuthenticationUIAllow`, `:kSecUseAuthenticationUIFail`, `:kSecUseAuthenticationUISkip`)
- `use_operation_prompt`

Validation rule: `synchronizable=true` cannot be combined with `accessible` values ending in `ThisDeviceOnly`.

## Metadata

`search_items` returns a fully-populated vector of the same item type.

For `GenericPasswordItem`:

- `service`, `account`, `label`, `synchronizable`, `accessible`, `access_group`, `description`, `comment`, `is_invisible`, `is_negative`, `generic_data`, `created_at`, `updated_at`

For `InternetPasswordItem`:

- `server`, `account`, `path`, `port`, `protocol`, `authentication_type`, `security_domain`, `label`, `synchronizable`, `accessible`, `access_group`, `description`, `comment`, `is_invisible`, `is_negative`, `created_at`, `updated_at`

## Errors

Typed errors are exposed for predictable failure handling:

- `UnsupportedPlatformError`
- `KeychainItemNotFoundError`
- `KeychainPermissionError`
- `KeychainOperationError`

## Disclaimer

Portions of this package were developed with the assistance of AI tools (GitHub Copilot). All AI-generated code was reviewed, tested, and modified when appropriate by a human author before being committed. The final implementation reflects human judgment and is the responsibility of the package maintainers.
