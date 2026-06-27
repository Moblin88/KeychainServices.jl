# Keychain Types and Entitlements

macOS provides two distinct keychain subsystems. Knowing which one you're
targeting is important because they have different security models,
portability characteristics, and entitlement requirements.

## The legacy keychain

The legacy keychain is the original macOS keychain, managed by
`securityd`. Items live in files on disk:

| Location | Description |
|:---------|:------------|
| `~/Library/Keychains/login.keychain-db` | User's login keychain — unlocked automatically at login |
| Any `.keychain-db` path | File keychain opened by path via `SecKeychainOpen` |

**Characteristics:**

- No entitlements required — any process on the system can read and write
  items in the login keychain, subject to normal access control prompts.
- Items can be read while the user is logged in, even from unsigned scripts
  and REPL sessions.
- File-based — portable across machines when copied, but not synced to
  iCloud.
- Deprecated as the primary recommendation by Apple since macOS 12, though
  still fully functional.

`LoginKeychain()` (the default) and `FileKeychain(path)` both target this
subsystem.

```julia
# Default — user's login keychain
item = GenericPasswordItem(service="com.example.app", account="alice")
add_item!(item, secret)

# Explicit file keychain
item = GenericPasswordItem(service="com.example.app", account="alice",
                           keychain=FileKeychain("/path/to/custom.keychain-db"))
```

## The Data Protection keychain

The Data Protection keychain uses the same underlying `SecItem` API but
stores items in a protected database managed by the system's Secure Enclave
encryption layer — the same subsystem used on iOS. It is selected by
setting `kSecUseDataProtectionKeychain = true` in query dictionaries, which
is exactly what `DataProtectionKeychain()` does.

!!! warning "Not available in the Julia REPL or most scripting contexts"
    The standard `julia` host process is an unsigned binary. It carries no
    code-signing entitlements, so **any attempt to use `DataProtectionKeychain()`
    from a plain Julia session — including the REPL, scripts, and CI runners —
    will raise `KeychainPermissionError` with `errSecMissingEntitlement`
    (-34018)**. This is an OS-level restriction, not a library limitation.

    Use `LoginKeychain()` (the default) for interactive and scripting use.
    `DataProtectionKeychain()` is only usable from a Julia binary compiled with
    `juliac` and packaged inside a properly signed `.app` bundle. See
    [Shipping a Julia binary with Data Protection keychain access](@ref shipping)
    below.

**Characteristics:**

- Items are bound to the device and cannot be extracted directly from the
  database.
- Supports hardware-backed access control: biometry, device passcode, and
  Secure Enclave constraints via [`AccessControlItem`](@ref).
- Supports iCloud Keychain sync for items with `synchronizable=true`.
- **Requires entitlements** — the process must be code-signed with at least
  one of:

  | Entitlement | Type | Purpose |
  |:------------|:-----|:--------|
  | `keychain-access-groups` | `Array<String>` | Explicit access group membership; at least one entry is required |
  | `com.apple.application-identifier` | `String` | Set automatically by Xcode for sandboxed apps |

  An unsigned process, or a process without these entitlements, receives
  `errSecMissingEntitlement` (-34018) and KeychainServices.jl raises
  [`KeychainPermissionError`](@ref).

You can check at runtime whether the current process has the required
entitlements:

```julia
if probe_data_protection_entitlement()
    item = GenericPasswordItem(service="com.example.app", account="alice",
                               keychain=DataProtectionKeychain())
    add_item!(item, secret)
else
    @warn "Data Protection keychain not available — falling back to login keychain"
    item = GenericPasswordItem(service="com.example.app", account="alice")
    add_item!(item, secret)
end
```

## Summary

| | `LoginKeychain()` | `DataProtectionKeychain()` | `FileKeychain(path)` |
|:--|:--|:--|:--|
| Entitlements required | No | Yes | No |
| Hardware-backed ACL | No | Yes | No |
| iCloud sync | No | Yes (opt-in) | No |
| Works from REPL / scripts | Yes | No | Yes |
| Recommended for apps | — | Yes | Legacy use |

---

## [Shipping a Julia binary with Data Protection keychain access](@id shipping)

To use `DataProtectionKeychain()` from a compiled Julia application, the
binary must run inside a properly signed macOS `.app` bundle that carries
the `keychain-access-groups` entitlement. The steps below describe the
complete workflow, adapted from
[SecretKeeper](https://github.com/Moblin88/SecretKeeper) — a reference
implementation of the same signing pipeline for a C binary.

### 1. Compile the Julia application

Julia 1.12 ships `juliac`, a native-code compiler that produces a
standalone executable:

```bash
# Compile main.jl to a self-contained binary
juliac --compile=all --output-exe build/myapp src/main.jl
```

`main.jl` should be a normal Julia file whose `main()` (or top-level code)
calls into KeychainServices.jl:

```julia
using KeychainServices

function store_credential(service, account, password)
    secret = Base.SecretBuffer!(collect(codeunits(password)))
    item   = GenericPasswordItem(service=service, account=account,
                                 keychain=DataProtectionKeychain())
    add_item!(item, secret)
    Base.shred!(secret)
end
```

### 2. Package as a `.app` bundle

macOS code-signing requires the binary to live inside an `.app` bundle
with a well-formed `Info.plist`. Create the structure manually:

```bash
APP=build/MyApp.app
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp build/myapp "$APP/Contents/MacOS/myapp"
```

Write `Contents/Info.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>      <string>myapp</string>
    <key>CFBundleIdentifier</key>      <string>com.example.myapp</string>
    <key>CFBundleName</key>            <string>MyApp</string>
    <key>CFBundlePackageType</key>     <string>APPL</string>
    <key>CFBundleShortVersionString</key> <string>1.0.0</string>
    <key>CFBundleVersion</key>         <string>1</string>
    <key>LSMinimumSystemVersion</key>  <string>14.0</string>
</dict>
</plist>
```

### 3. Obtain a provisioning profile with fastlane

[fastlane sigh](https://docs.fastlane.tools/actions/sigh/) downloads a
provisioning profile from the Apple Developer portal. The profile must
include the `keychain-access-groups` entitlement for your bundle ID.

Install fastlane, then create a `Fastfile`:

```ruby
default_platform(:mac)

platform :mac do
  lane :generate_profile do
    sigh(
      app_identifier: "com.example.myapp",
      platform:       "macos",
      development:    true,
      force:          true,
      output_path:    "build/profiles",
    )
  end
end
```

Run it:

```bash
FASTLANE_USER=you@example.com fastlane mac generate_profile
# → build/profiles/com.example.myapp.mobileprovision
```

### 4. Embed the profile and sign the bundle

Embed the profile, then use `codesign` with an entitlements plist that
matches what the profile grants:

```bash
TEAM_ID="ABCDE12345"
BUNDLE_ID="com.example.myapp"
PROFILE="build/profiles/com.example.myapp.mobileprovision"

# Embed the provisioning profile
cp "$PROFILE" "$APP/Contents/embedded.provisionprofile"

# Write the entitlements plist
cat > /tmp/entitlements.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>com.apple.application-identifier</key>
  <string>${TEAM_ID}.${BUNDLE_ID}</string>
  <key>com.apple.developer.team-identifier</key>
  <string>${TEAM_ID}</string>
  <key>keychain-access-groups</key>
  <array>
    <string>${TEAM_ID}.${BUNDLE_ID}</string>
  </array>
</dict>
</plist>
EOF

# Resolve a signing identity
IDENTITY=$(security find-identity -v -p codesigning \
  | grep -E "Apple Development|Apple Distribution" \
  | head -n1 \
  | sed -E 's/.*"([^"]+)".*/\1/')

# Sign
codesign --force --deep --options runtime \
         --entitlements /tmp/entitlements.plist \
         --sign "$IDENTITY" \
         "$APP"

# Verify
codesign --verify --deep --strict "$APP"
```

The `keychain-access-groups` entitlement embedded in the signed binary is
exactly what `probe_data_protection_entitlement()` reads via
`SecTaskCopyValueForEntitlement`. Once signed, any call to
`DataProtectionKeychain()` from within this app will succeed without
raising [`KeychainPermissionError`](@ref).

### 5. Run from the app bundle

Execute the binary from its location inside the bundle — the entitlements
are bound to the bundle path:

```bash
build/MyApp.app/Contents/MacOS/myapp
```

Running the binary directly from outside the bundle (e.g. copying it to
`/usr/local/bin`) removes it from the signed bundle context and the
entitlements will not apply.
