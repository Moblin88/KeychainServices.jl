"""
    AccessControlFlags

Bit-flag constants for `SecAccessControlCreateWithFlags`. Combine flags with `|`:

```julia
flags = AccessControlFlags.BiometryAny | AccessControlFlags.DevicePasscode
```

| Constant              | Bit    | Description                               |
|:----------------------|:-------|:------------------------------------------|
| `UserPresence`        | `1<<0` | Biometry or device passcode               |
| `BiometryAny`         | `1<<1` | Any enrolled biometry                     |
| `BiometryCurrentSet`  | `1<<3` | Currently-enrolled biometry set           |
| `DevicePasscode`      | `1<<4` | Device passcode only                      |
| `Companion`           | `1<<5` | Apple Watch / companion device            |
| `Or`                  | `1<<14`| Satisfy any one of the attached constraints|
| `And`                 | `1<<15`| Satisfy all of the attached constraints   |
| `PrivateKeyUsage`     | `1<<30`| For private-key operations only           |
| `ApplicationPassword` | `1<<31`| Additional application-level password     |

Values match `SecAccessControlCreateFlags` from `<Security/SecAccessControl.h>` (macOS 15 SDK).
"""
module AccessControlFlags
    const UserPresence        = UInt64(1 << 0)
    const BiometryAny         = UInt64(1 << 1)
    const BiometryCurrentSet  = UInt64(1 << 3)
    const DevicePasscode      = UInt64(1 << 4)
    const Companion           = UInt64(1 << 5)
    const Or                  = UInt64(1 << 14)
    const And                 = UInt64(1 << 15)
    const PrivateKeyUsage     = UInt64(1 << 30)
    const ApplicationPassword = UInt64(1 << 31)
end

"""
    AccessControlItem(accessible::Symbol, flags::UInt64 = 0)

Specifies Data Protection keychain access-control constraints for a keychain item.
An `AccessControlItem` in a [`GenericPasswordItem`](@ref)'s `access_control` field
causes a `SecAccessControlRef` to be created via `SecAccessControlCreateWithFlags`
and stored under `kSecAttrAccessControl`.

`accessible` must be one of the `kSecAttrAccessible*` constants:

| Symbol | When accessible |
|:-------|:----------------|
| `:kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` | Only when passcode set; device-only |
| `:kSecAttrAccessibleWhenUnlockedThisDeviceOnly`    | While unlocked; device-only |
| `:kSecAttrAccessibleWhenUnlocked`                  | While unlocked |
| `:kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`| After first unlock; device-only |
| `:kSecAttrAccessibleAfterFirstUnlock`              | After first unlock |

`flags` is a bitwise combination of [`AccessControlFlags`](@ref) constants.

## Example

```julia
ctrl = AccessControlItem(
    :kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
    AccessControlFlags.BiometryAny | AccessControlFlags.DevicePasscode,
)
item = GenericPasswordItem(service="app", account="user", access_control=ctrl)
```
"""
struct AccessControlItem
    accessible::Symbol
    flags::UInt64

    AccessControlItem(accessible::Symbol, flags::UInt64 = UInt64(0)) = new(accessible, flags)
end
