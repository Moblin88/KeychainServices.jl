"""
    KeychainTarget

Abstract type for specifying which keychain an item is stored in or queried from.

Concrete subtypes:
- [`DataProtectionKeychain`](@ref) — modern iOS-style Data Protection keychain (default)
- [`LoginKeychain`](@ref) — the user's legacy login keychain
- [`FileKeychain`](@ref) — an explicit legacy keychain file
"""
abstract type KeychainTarget end

"""
    DataProtectionKeychain()

Targets the modern Data Protection keychain by setting `kSecUseDataProtectionKeychain = true`
in query dictionaries. Items stored here are bound to the device and managed by the system's
encryption layer. Requires the `keychain-access-groups` entitlement when used from a sandboxed
or provisioned process.
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

Targets a specific legacy file-based keychain located at `path`. Adds a `kSecUseKeychain`
entry to query dictionaries; the keychain file is opened via `SecKeychainOpen` for each
operation.
"""
struct FileKeychain <: KeychainTarget
    path::String
end

# Returns the pairs to merge into a SecItem query dictionary for the given target.
_keychain_target_pairs(::DataProtectionKeychain) = Pair{Symbol,Any}[:kSecUseDataProtectionKeychain => true]
_keychain_target_pairs(::LoginKeychain)           = Pair{Symbol,Any}[]
_keychain_target_pairs(kc::FileKeychain)          = Pair{Symbol,Any}[:kSecUseKeychain => kc]
