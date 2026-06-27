# KeychainServices

[![Build Status](https://github.com/Moblin88/KeychainServices.jl/actions/workflows/CI.yml/badge.svg?branch=main)](https://github.com/Moblin88/KeychainServices.jl/actions/workflows/CI.yml?query=branch%3Amain)
[![Coverage](https://codecov.io/gh/Moblin88/KeychainServices.jl/branch/main/graph/badge.svg)](https://codecov.io/gh/Moblin88/KeychainServices.jl)
[![Docs (stable)](https://img.shields.io/badge/docs-stable-blue.svg)](https://Moblin88.github.io/KeychainServices.jl/stable/)
[![Docs (dev)](https://img.shields.io/badge/docs-dev-blue.svg)](https://Moblin88.github.io/KeychainServices.jl/dev/)

KeychainServices.jl is a direct Julia wrapper over Apple's Keychain Services API for working with generic password items on macOS.

The current API is scoped to generic password items. Other Keychain item classes such as internet passwords, certificates, keys, and identities are not implemented yet.

The package calls Security.framework natively through Julia `@ccall` bindings. It does not shell out to the `security` command-line tool.

All keychain operations target the Data Protection keychain. This behavior is automatic and not configurable.

## Platform Support

- macOS: supported
- Other platforms: loading succeeds, but Keychain operations raise `UnsupportedPlatformError`

You can check if the current machine is Apple/macOS with Julia built-ins:

```julia
is_apple = Sys.isapple()
```

## API

Direct-item API:

```julia
using KeychainServices

secret = Base.SecretBuffer!(collect(codeunits("s3cr3t")))
rotated_secret = Base.SecretBuffer!(collect(codeunits("n3w-s3cr3t")))
item = GenericPasswordItem(service="com.example.app", account="alice")

add_item!(item, secret)

result = copy_matching(item; return_data=true, return_attributes=true)
password = result.secret
label = result.item.label

update_item!(item, GenericPasswordItem(label="Primary login"); secret=rotated_secret)

delete_item!(item)

Base.shred!(secret)
Base.shred!(rotated_secret)
Base.shred!(password)
```

Fields left as `nothing` are omitted from the underlying Security.framework query dictionary.

Secrets must be provided as `Base.SecretBuffer` values. `copy_matching` also returns secrets as `Base.SecretBuffer`, which lets callers shred them explicitly after use. Converting secrets back into `String` defeats that memory-handling benefit.

Optional field configuration:

```julia
using KeychainServices

secret = Base.SecretBuffer!(collect(codeunits("s3cr3t")))
sync_item = GenericPasswordItem(
	service="com.example.app",
	account="alice",
	synchronizable=true,
	accessible=:kSecAttrAccessibleWhenUnlocked,
)

add_item!(sync_item, secret)
result = copy_matching(sync_item; return_data=true)
Base.shred!(secret)
Base.shred!(result.secret)
```

Additional supported generic-password attributes:

- `accessible` (for example `:kSecAttrAccessibleWhenUnlocked`)
- `access_group`
- `description`
- `comment`
- `is_invisible`
- `is_negative`
- `generic_data` (`Vector{UInt8}`)
- `access_control` (`Ptr{Cvoid}`, advanced usage)

Query-time use restrictions for `copy_matching`:

- `use_authentication_ui` (`:kSecUseAuthenticationUIAllow`, `:kSecUseAuthenticationUIFail`, `:kSecUseAuthenticationUISkip`)
- `use_operation_prompt`

Validation rule: `synchronizable=true` cannot be combined with `accessible` values ending in `ThisDeviceOnly`.

Migration note: the `data_protection_keychain` keyword was removed from `GenericPasswordItem` because Data Protection keychain targeting is now always enforced.

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

## Migration From Keyring.jl

This refactor is intentionally breaking.

- `using Keyring` becomes `using KeychainServices`
- Positional helpers like `set_password!` / `get_password` were replaced by typed `GenericPasswordItem` CRUD APIs
- The cross-platform provider registry and Windows/Linux stubs were removed
- The package is now explicitly scoped to Apple's Keychain Services API
- The current implementation only covers generic password items
