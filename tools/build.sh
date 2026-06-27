#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
SRC="$SCRIPT_DIR/keychain_helper.c"
ENTITLEMENTS="$SCRIPT_DIR/keychain.entitlements"
OUT="$BUILD_DIR/keychain_helper"

# Modes:
#   dev     - Sign the raw binary with an Apple Development identity + entitlements file.
#   adhoc   - Ad-hoc sign the raw binary + entitlements file.
#   none    - No code signing.
#   profile - Build a .app, embed provisioning profile, derive entitlements from profile, then sign.
SIGN_MODE="${SIGN_MODE:-dev}"
IDENTITY="${IDENTITY:-Apple Development: moblin88@me.com (3XUQ4C3KU2)}"
PROFILE_PATH="${PROFILE_PATH:-}"
APP_BUNDLE_ID="${APP_BUNDLE_ID:-com.keychainservices.test}"

mkdir -p "$BUILD_DIR"

cc "$SRC" \
  -framework Security \
  -framework CoreFoundation \
  -o "$OUT"

if ! grep -q "kSecUseDataProtectionKeychain" "$SRC"; then
  echo "ERROR: Probe source does not reference kSecUseDataProtectionKeychain." >&2
  echo "Refusing to build because Data Protection keychain usage is required." >&2
  exit 1
fi

print_signing_details() {
  local artifact="$1"
  echo "Embedded entitlements for $artifact:"
  codesign -dv --entitlements :- "$artifact" 2>&1 || true
  echo
  echo "Signing flags for $artifact:"
  codesign -dvv "$artifact" 2>&1 | grep -E "flags=|TeamIdentifier=" || true
}

find_matching_profile() {
  local -a roots=(
    "$HOME/Library/MobileDevice/Provisioning Profiles"
    "$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles"
  )
  local root=""
  local candidate=""
  local decoded=""
  local team_id=""
  local app_id_pattern=""
  local expected_app_id=""

  for root in "${roots[@]}"; do
    [[ -d "$root" ]] || continue

    while IFS= read -r -d '' candidate; do
      decoded="$BUILD_DIR/profile.scan.$$.plist"
      if ! security cms -D -i "$candidate" > "$decoded" 2>/dev/null; then
        rm -f "$decoded"
        continue
      fi

      team_id="$(/usr/libexec/PlistBuddy -c 'Print :TeamIdentifier:0' "$decoded" 2>/dev/null || true)"
      app_id_pattern="$(/usr/libexec/PlistBuddy -c 'Print :Entitlements:com.apple.application-identifier' "$decoded" 2>/dev/null || true)"
      if [[ -z "$app_id_pattern" ]]; then
        app_id_pattern="$(/usr/libexec/PlistBuddy -c 'Print :Entitlements:application-identifier' "$decoded" 2>/dev/null || true)"
      fi

      rm -f "$decoded"

      if [[ -z "$team_id" || -z "$app_id_pattern" ]]; then
        continue
      fi

      expected_app_id="${team_id}.${APP_BUNDLE_ID}"
      if [[ "$expected_app_id" == $app_id_pattern ]]; then
        echo "$candidate"
        return 0
      fi
    done < <(find "$root" -type f -name '*.mobileprovision' -print0 2>/dev/null)
  done

  return 1
}

case "$SIGN_MODE" in
  none)
    echo "Built without signing: $OUT"
    ;;

  adhoc)
    codesign --force --sign - --options runtime --entitlements "$ENTITLEMENTS" "$OUT"
    echo "Built with ad-hoc signing: $OUT"
    print_signing_details "$OUT"
    ;;

  dev)
    codesign --force --sign "$IDENTITY" --options runtime --entitlements "$ENTITLEMENTS" "$OUT"
    echo "Built with development signing: $OUT"
    print_signing_details "$OUT"
    ;;

  profile)
    if [[ -z "$PROFILE_PATH" ]]; then
      PROFILE_PATH="$(find_matching_profile || true)"
      if [[ -n "$PROFILE_PATH" ]]; then
        echo "Auto-selected provisioning profile: $PROFILE_PATH"
      fi
    fi

    if [[ -z "$PROFILE_PATH" || ! -f "$PROFILE_PATH" ]]; then
      echo "ERROR: No matching provisioning profile found for APP_BUNDLE_ID=$APP_BUNDLE_ID." >&2
      echo "Searched: ~/Library/MobileDevice/Provisioning Profiles and ~/Library/Developer/Xcode/UserData/Provisioning Profiles" >&2
      echo "Set PROFILE_PATH explicitly to override discovery." >&2
      exit 1
    fi

    PROFILE_PLIST="$BUILD_DIR/profile.decoded.plist"
    AUTO_ENTITLEMENTS="$BUILD_DIR/profile.entitlements.plist"
    APP_DIR="$BUILD_DIR/EntitledProbe.app"
    APP_CONTENTS="$APP_DIR/Contents"
    APP_MACOS="$APP_CONTENTS/MacOS"
    APP_EXEC="$APP_MACOS/entitled_keychain_probe"
    APP_INFO="$APP_CONTENTS/Info.plist"
    APP_PROFILE="$APP_CONTENTS/embedded.provisionprofile"

    rm -rf "$APP_DIR"
    mkdir -p "$APP_MACOS"

    cp "$OUT" "$APP_EXEC"
    cp "$PROFILE_PATH" "$APP_PROFILE"

    security cms -D -i "$PROFILE_PATH" > "$PROFILE_PLIST"

    TEAM_ID="$(/usr/libexec/PlistBuddy -c 'Print :TeamIdentifier:0' "$PROFILE_PLIST")"
    PROFILE_APP_ID="$(/usr/libexec/PlistBuddy -c 'Print :Entitlements:com.apple.application-identifier' "$PROFILE_PLIST" 2>/dev/null || true)"
    if [[ -z "$PROFILE_APP_ID" ]]; then
      PROFILE_APP_ID="$(/usr/libexec/PlistBuddy -c 'Print :Entitlements:application-identifier' "$PROFILE_PLIST" 2>/dev/null || true)"
    fi

    if [[ -z "$TEAM_ID" || -z "$PROFILE_APP_ID" ]]; then
      echo "ERROR: Could not read TeamIdentifier/application-identifier from provisioning profile." >&2
      exit 1
    fi

    if [[ "$PROFILE_APP_ID" == *"*" ]]; then
      APP_ID="${TEAM_ID}.${APP_BUNDLE_ID}"
    else
      APP_ID="$PROFILE_APP_ID"
    fi

    cat > "$AUTO_ENTITLEMENTS" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.application-identifier</key>
    <string>${APP_ID}</string>
    <key>com.apple.developer.team-identifier</key>
    <string>${TEAM_ID}</string>
    <key>keychain-access-groups</key>
    <array>
        <string>${APP_ID}</string>
    </array>
</dict>
</plist>
EOF

    cat > "$APP_INFO" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleExecutable</key>
    <string>entitled_keychain_probe</string>
    <key>CFBundleIdentifier</key>
    <string>${APP_BUNDLE_ID}</string>
    <key>CFBundleName</key>
    <string>EntitledProbe</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
</dict>
</plist>
EOF

    codesign --force --sign "$IDENTITY" --options runtime --entitlements "$AUTO_ENTITLEMENTS" "$APP_DIR"

    echo "Built app bundle with profile signing: $APP_DIR"
    echo "Executable: $APP_EXEC"
    echo "Profile TeamIdentifier: $TEAM_ID"
    echo "Resolved app identifier: $APP_ID"
    print_signing_details "$APP_DIR"
    ;;

  *)
    echo "ERROR: Unsupported SIGN_MODE=$SIGN_MODE (expected: dev|adhoc|none|profile)" >&2
    exit 1
    ;;
esac

if [[ "$SIGN_MODE" != "profile" ]]; then
  echo
  print_signing_details "$OUT"
fi