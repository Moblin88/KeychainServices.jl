"""
    KeychainTarget

Abstract type for specifying which keychain an item is stored in or queried from.

Concrete subtypes:
- [`LoginKeychain`](@ref) — the user's legacy login keychain *(default)*
- [`DataProtectionKeychain`](@ref) — modern iOS-style Data Protection keychain
- [`FileKeychain`](@ref) — an explicit legacy keychain file
"""
abstract type KeychainTarget end

"""
    DataProtectionKeychain()

Targets the modern Data Protection keychain by setting `kSecUseDataProtectionKeychain = true`.
Items stored here are bound to the device and managed by the system's encryption layer.
Requires the `keychain-access-groups` entitlement when used from a sandboxed or provisioned process.
"""
struct DataProtectionKeychain <: KeychainTarget end

"""
    LoginKeychain()

Targets the user's legacy login keychain (typically `~/Library/Keychains/login.keychain-db`)
without enabling Data Protection keychain semantics. No `kSecUseDataProtectionKeychain` key is
added to query dictionaries.
"""
struct LoginKeychain <: KeychainTarget end

"""
    FileKeychain(path::String)

Targets a specific legacy file-based keychain located at `path`. The keychain
file is opened via `SecKeychainOpen` for each operation, setting `kSecUseKeychain`
(for `SecItemAdd`) and `kSecMatchSearchList` (for copy/update/delete).
"""
struct FileKeychain <: KeychainTarget
    path::String
end