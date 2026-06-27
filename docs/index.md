# KeychainServices.jl

KeychainServices.jl is a direct wrapper over Apple's Keychain Services API for generic password items.

Other Keychain item classes such as internet passwords, certificates, keys, and identities are not implemented yet.

## Requirements

- macOS
- Julia 1.10.10 or newer

You can check if the current machine is Apple/macOS with Julia built-ins:

```julia
is_apple = Sys.isapple()
```

## Usage

```julia
using KeychainServices

secret = Base.SecretBuffer!(collect(codeunits("s3cr3t")))
rotated_secret = Base.SecretBuffer!(collect(codeunits("n3w-s3cr3t")))
item = GenericPasswordItem(service="com.example.app", account="alice")

add_item!(item, secret)

result = copy_matching(item; return_data=true, return_attributes=true)
password = result.secret

update_item!(item, GenericPasswordItem(label="Primary login"); secret=rotated_secret)

delete_item!(item)

Base.shred!(secret)
Base.shred!(rotated_secret)
Base.shred!(password)
```

Fields left as `nothing` are omitted from the underlying Security.framework query dictionary.

Secrets must be passed as `Base.SecretBuffer`, and returned secrets also arrive as `Base.SecretBuffer`. Avoid converting them back into `String` unless you intentionally accept the loss of secure shredding semantics.

If you need iCloud Keychain synchronization, set the item field directly:

```julia
secret = Base.SecretBuffer!(collect(codeunits("s3cr3t")))
sync_item = GenericPasswordItem(
	service="com.example.app",
	account="alice",
	synchronizable=true,
)

add_item!(sync_item, secret)
Base.shred!(secret)
```

## Notes

- The package uses Security.framework through native Julia `@ccall` bindings.
- Operations are driven by typed `GenericPasswordItem` values.
- On non-macOS platforms, operations raise `UnsupportedPlatformError`.