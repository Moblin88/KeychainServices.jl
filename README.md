# KeychainServices

[![Build Status](https://github.com/Moblin88/KeychainServices.jl/actions/workflows/CI.yml/badge.svg?branch=main)](https://github.com/Moblin88/KeychainServices.jl/actions/workflows/CI.yml?query=branch%3Amain)
[![Coverage](https://codecov.io/gh/Moblin88/KeychainServices.jl/branch/main/graph/badge.svg)](https://codecov.io/gh/Moblin88/KeychainServices.jl)
[![Docs (stable)](https://img.shields.io/badge/docs-stable-blue.svg)](https://Moblin88.github.io/KeychainServices.jl/stable/)
[![Docs (dev)](https://img.shields.io/badge/docs-dev-blue.svg)](https://Moblin88.github.io/KeychainServices.jl/dev/)

KeychainServices.jl is a direct Julia wrapper over Apple's Keychain Services API for working with generic password items on macOS.

The current API is scoped to generic password items. Other Keychain item classes such as internet passwords, certificates, keys, and identities are not implemented yet.

The package calls Security.framework natively through Julia `@ccall` bindings. It does not shell out to the `security` command-line tool.

## Platform Support

- macOS: supported
- Other platforms: loading succeeds, but Keychain operations raise `UnsupportedPlatformError`

You can check if the current machine is Apple/macOS with Julia built-ins:

```julia
is_apple = Sys.isapple()
```

## API

Direct-item API (targets the login keychain by default — no entitlements required):

```julia
using KeychainServices

secret  = Base.SecretBuffer("s3cr3t")
rotated = Base.SecretBuffer("n3w-s3cr3t")
item    = GenericPasswordItem(service="com.example.app", account="alice")

add_item!(item, secret)

password = copy_secret(item)   # Base.SecretBuffer, seekstarted and ready to read
results  = search_items(item)  # Vector{GenericPasswordItem} with metadata + timestamps
label    = results[1].label

update_item!(item, GenericPasswordItem(label="Primary login"); secret=rotated)

delete_item!(item)

Base.shred!(secret)
Base.shred!(rotated)
Base.shred!(password)
```

Fields left as `nothing` are omitted from the underlying Security.framework query dictionary.

Secrets may be passed as a `Base.SecretBuffer` (or any `IO`), an
`AbstractVector{UInt8}`, or an `AbstractString`. `copy_secret` returns a
`Base.SecretBuffer` (seekstarted, ready to read) by default, or writes into
a caller-supplied `IO` via the `into` keyword.

Optional field configuration:

```julia
using KeychainServices

secret = Base.SecretBuffer("s3cr3t")
sync_item = GenericPasswordItem(
	service="com.example.app",
	account="alice",
	synchronizable=true,
	accessible=:kSecAttrAccessibleWhenUnlocked,
)

add_item!(sync_item, secret)
password = copy_secret(sync_item)
Base.shred!(secret)
Base.shred!(password)
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

> **Note:** `DataProtectionKeychain()` and `AccessControlItem` require the process to be
> code-signed with the `keychain-access-groups` entitlement. The standard `julia` host is
> unsigned, so using these from the REPL, scripts, or CI raises `KeychainPermissionError`.
> Use `LoginKeychain()` (the default) for interactive and scripting contexts. See the
> [docs](https://Moblin88.github.io/KeychainServices.jl/dev/keychain-types/) for the full
> signed-app workflow.

Query-time use restrictions for `copy_matching`:

- `use_authentication_ui` (`:kSecUseAuthenticationUIAllow`, `:kSecUseAuthenticationUIFail`, `:kSecUseAuthenticationUISkip`)
- `use_operation_prompt`

Validation rule: `synchronizable=true` cannot be combined with `accessible` values ending in `ThisDeviceOnly`.

## Metadata

`copy_matching` returns a `KeychainItemResult`. For generic password items, the result can include:

- `service`
- `account`
- `label`
- `synchronizable`
- `accessible`
- `access_group`
- `description`
- `comment`
- `is_invisible`
- `is_negative`
- `generic_data`
- `created_at`
- `updated_at`
- `secret`

## Errors

Typed errors are exposed for predictable failure handling:

- `UnsupportedPlatformError`
- `KeychainItemNotFoundError`
- `KeychainPermissionError`
- `KeychainOperationError`
