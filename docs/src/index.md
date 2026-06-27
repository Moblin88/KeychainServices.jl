# KeychainServices.jl

[![Build Status](https://github.com/Moblin88/KeychainServices.jl/actions/workflows/CI.yml/badge.svg?branch=main)](https://github.com/Moblin88/KeychainServices.jl/actions/workflows/CI.yml)
[![Coverage](https://codecov.io/gh/Moblin88/KeychainServices.jl/branch/main/graph/badge.svg)](https://codecov.io/gh/Moblin88/KeychainServices.jl)
[![Docs (stable)](https://img.shields.io/badge/docs-stable-blue.svg)](https://Moblin88.github.io/KeychainServices.jl/stable/)
[![Docs (dev)](https://img.shields.io/badge/docs-dev-blue.svg)](https://Moblin88.github.io/KeychainServices.jl/dev/)

KeychainServices.jl is a native Julia wrapper over Apple's [Keychain Services](https://developer.apple.com/documentation/security/keychain-services) API.

It calls Security.framework directly through Julia's `@ccall` bindings — no shell-outs, no helper binaries.

Supported item classes:

- `kSecClassGenericPassword` — generic passwords ([`GenericPasswordItem`](@ref))
- `kSecClassInternetPassword` — internet / URL-keyed passwords ([`InternetPasswordItem`](@ref))

## Platform

- **macOS**: fully supported.
- **Other platforms**: the module loads and exports all types, but operations raise [`UnsupportedPlatformError`](@ref).

## Quick start

### Generic passwords

```julia
using KeychainServices

secret  = Base.SecretBuffer("s3cr3t")
rotated = Base.SecretBuffer("n3w-s3cr3t")
item    = GenericPasswordItem(service="com.example.app", account="alice")

add_item!(item, secret)

password = copy_secret(item)         # Base.SecretBuffer, seekstarted and ready to read
results  = search_items(item)        # Vector{GenericPasswordItem} with all metadata
label    = results[1].label
created  = results[1].created_at

update_item!(item, GenericPasswordItem(label="Primary login"), rotated)
delete_item!(item)

Base.shred!(secret)
Base.shred!(rotated)
Base.shred!(password)
```

### Internet passwords

```julia
using KeychainServices

secret = Base.SecretBuffer("s3cr3t")
item   = InternetPasswordItem(
    server   = "api.example.com",
    account  = "alice",
    protocol = :kSecAttrProtocolHTTPS,
    port     = 443,
)

add_item!(item, secret)

password = copy_secret(item)         # Base.SecretBuffer, seekstarted and ready to read
results  = search_items(item)        # Vector{InternetPasswordItem} with all metadata

update_item!(item, InternetPasswordItem(label="Primary API key"))
delete_item!(item)

Base.shred!(secret)
Base.shred!(password)
```

## Keychain targets

The `keychain` field of [`GenericPasswordItem`](@ref) and [`InternetPasswordItem`](@ref) controls which keychain backend is used:

| Type | Behaviour |
|:-----|:----------|
| `LoginKeychain()` *(default)* | User's login keychain (macOS system default) |
| `DataProtectionKeychain()` | Modern Data Protection keychain — adds `kSecUseDataProtectionKeychain=true` |
| `FileKeychain(path)` | Explicit legacy keychain file |

!!! warning "DataProtectionKeychain requires a signed app bundle"
    The standard `julia` host is unsigned and carries no entitlements.
    Using `DataProtectionKeychain()` from the REPL, scripts, or CI will raise
    `KeychainPermissionError` (`errSecMissingEntitlement`). It is only usable
    from a `juliac`-compiled binary inside a signed `.app` bundle. See the
    [Keychain Types & Entitlements](@ref) guide for the full workflow.
    Use `LoginKeychain()` (the default) in all other contexts.

```julia
# Legacy login keychain
item = GenericPasswordItem(service="com.example.app", account="alice",
                           keychain=LoginKeychain())

# Internet password on a specific keychain file
item = InternetPasswordItem(server="api.example.com", account="alice",
                            keychain=FileKeychain("/path/to/my.keychain"))
```

## Access control (Data Protection keychain)

!!! warning
    Access control via `AccessControlItem` requires `DataProtectionKeychain()`,
    which is only available from a signed app bundle. See the warning above.

Use [`AccessControlItem`](@ref) for hardware-backed or biometry-protected items:

```julia
ctrl = AccessControlItem(
    :kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
    AccessControlFlags.BiometryAny | AccessControlFlags.DevicePasscode,
)
item = GenericPasswordItem(service="com.example.app", account="alice",
                           access_control=ctrl)
add_item!(item, secret)
```

## Design

The low-level `_cf_dict` builder accepts any iterable of
`(Symbol, Any)` pairs and marshals Julia values into CF objects through `_cf_dict_set!`
method dispatch:

| Julia type | CF type |
|:-----------|:--------|
| `Symbol` | CF constant (via `cglobal`) |
| `AbstractString` | `CFStringRef` |
| `Bool` | `kCFBooleanTrue` / `kCFBooleanFalse` |
| `Integer` | `CFNumberRef` (used for `kSecAttrPort`) |
| `AbstractVector{UInt8}` | `CFDataRef` |
| `Base.SecretBuffer` | `CFDataRef` (bytes zeroed after use) |
| [`AccessControlItem`](@ref) | `SecAccessControlRef` |
| [`FileKeychain`](@ref) | `SecKeychainRef` (via `SecKeychainOpen`) |

[`GenericPasswordItem`](@ref) and [`InternetPasswordItem`](@ref) implement `Base.pairs` to expose their Security.framework
key-value pairs, making the top-level CRUD functions thin wrappers:

```julia
# These two are equivalent
add_item!(item, secret)

# … what it does under the hood:
KeychainServices._sec_item_add([pairs(item)..., :kSecValueData => secret])
```
