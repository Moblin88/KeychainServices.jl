# Entitlements Memo for KeychainServices.jl

## Purpose
This memo explains how macOS entitlements work for Keychain Services, which identity and entitlement properties matter for this package, and why CLI execution can fail with missing entitlement errors when Data Protection keychain behavior is required.

## Executive Summary
- Entitlements are signed claims attached to the executable that makes a protected API call.
- Keychain Services authorization depends on the calling process identity and entitlement-derived access group membership.
- `errSecMissingEntitlement` (`-34018`) indicates required entitlement context is missing for the attempted keychain operation.
- Shell scripts and environment variables cannot grant entitlements at runtime.
- For Data Protection keychain paths on macOS, non-app CLI execution frequently lacks the expected entitlement context.

## How Entitlements Work on macOS
1. Entitlements are embedded in a code signature and cryptographically bound to a binary.
2. At runtime, macOS validates the calling process identity and entitlements when protected APIs are used.
3. Keychain access decisions are based on process identity and access-group membership derived from signed data.
4. If membership or required identity context is missing, Security.framework operations can fail.

## Keychain Identity and Access Group Inputs
For keychain access-group decisions, Apple documentation points to these identity/entitlement sources:
- `application-identifier` (or `com.apple.application-identifier` on macOS)
- `keychain-access-groups`
- `com.apple.security.application-groups`

These values define which groups an app/process belongs to for keychain sharing and access checks.

## What Matters for This Package
### Relevant
- Generic password CRUD through `SecItemAdd`, `SecItemCopyMatching`, `SecItemUpdate`, and `SecItemDelete`.
- Data Protection keychain behavior (for example using `kSecUseDataProtectionKeychain`).
- Signed process identity that can satisfy keychain entitlement checks.

### Not Required for Core Scope
- Unrelated restricted capabilities (for example endpoint-security daemon entitlements) are not needed for generic password CRUD.

## Why CLI Workflows Often Hit `-34018`
A plain Julia CLI process typically does not run as a signed app identity with entitlement/provisioning context equivalent to an app target configured in Xcode. When operations require that context, calls can fail with `errSecMissingEntitlement` (`-34018`).

## What Does Not Work as a Fix
- Wrapping calls in a shell script.
- Setting environment variables to try to "grant" entitlements.
- Launching an unentitled child executable from an entitled parent and expecting entitlement transfer.

These approaches do not change the effective entitlements of the process actually executing Security.framework calls.

## Viable Runtime Strategies
1. Run keychain calls in a properly signed and entitled host executable.
2. Delegate keychain operations to an entitled helper process/service.
3. Maintain explicit compatibility behavior for CLI contexts where entitlement-backed paths are unavailable.

## References
### Apple
1. `errSecMissingEntitlement`
   https://developer.apple.com/documentation/security/errsecmissingentitlement
2. Sharing access to keychain items among a collection of apps
   https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps
3. `SecItemAdd`
   https://developer.apple.com/documentation/security/secitemadd(_:_:)
4. Signing a daemon with a restricted entitlement
   https://developer.apple.com/documentation/xcode/signing-a-daemon-with-a-restricted-entitlement

### Supporting Third-Party Documentation
1. Electron code signing guide
   https://www.electronjs.org/docs/latest/tutorial/code-signing
2. `@electron/osx-sign` repository and documentation
   https://github.com/electron/osx-sign
3. Tauri macOS signing guide
   https://v1.tauri.app/v1/guides/distribution/sign-macos/
