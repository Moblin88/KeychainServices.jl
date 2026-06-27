# API Reference

## Keychain item types

```@docs
AbstractKeychainItem
GenericPasswordItem
InternetPasswordItem
```

## Keychain targets

```@docs
KeychainTarget
DataProtectionKeychain
LoginKeychain
FileKeychain
```

## Access control

```@docs
AccessControlItem
AccessControlFlags
```

## CRUD operations

```@docs
add_item!
search_items
copy_secret
update_item!
delete_item!
Base.pairs(::KeychainServices.GenericPasswordItem)
Base.pairs(::KeychainServices.InternetPasswordItem)
```

## Entitlement probe

```@docs
probe_data_protection_entitlement
```

## Error types

```@docs
KeychainServicesError
KeychainOperationError
UnsupportedPlatformError
KeychainItemNotFoundError
KeychainPermissionError
```
