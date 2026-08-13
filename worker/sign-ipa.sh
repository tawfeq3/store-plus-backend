#!/bin/bash

set -euo pipefail

INPUT_IPA="${1:?Missing input IPA}"
P12_FILE="${2:?Missing P12 file}"
P12_PASSWORD_FILE="${3:?Missing P12 password file}"
PROFILE_FILE="${4:?Missing mobileprovision file}"
OUTPUT_IPA="${5:?Missing output IPA}"

WORK_DIR="$(mktemp -d)"

cleanup() {
    security delete-keychain "$WORK_DIR/signing.keychain-db" \
        >/dev/null 2>&1 || true

    rm -rf "$WORK_DIR"
}

trap cleanup EXIT

mkdir -p "$WORK_DIR/payload"

echo "Preparing signing environment..."

P12_PASSWORD="$(cat "$P12_PASSWORD_FILE")"

if [ -z "$P12_PASSWORD" ]; then
    echo "P12 password is empty."
    exit 1
fi

if [ ! -f "$INPUT_IPA" ]; then
    echo "Input IPA not found."
    exit 1
fi

if [ ! -f "$P12_FILE" ]; then
    echo "P12 file not found."
    exit 1
fi

if [ ! -f "$PROFILE_FILE" ]; then
    echo "MobileProvision file not found."
    exit 1
fi

echo "Creating temporary keychain..."

KEYCHAIN="$WORK_DIR/signing.keychain-db"

security create-keychain \
    -p "$WORK_DIR/keychain-password" \
    "$KEYCHAIN"

security set-keychain-settings \
    -lut 21600 \
    "$KEYCHAIN"

security unlock-keychain \
    -p "$WORK_DIR/keychain-password" \
    "$KEYCHAIN"

security list-keychains \
    -d user \
    -s "$KEYCHAIN"

echo "Importing P12..."

security import \
    "$P12_FILE" \
    -k "$KEYCHAIN" \
    -P "$P12_PASSWORD" \
    -T /usr/bin/codesign \
    -T /usr/bin/security

security set-key-partition-list \
    -S apple-tool:,apple: \
    -s \
    -k "$WORK_DIR/keychain-password" \
    "$KEYCHAIN"

echo "Extracting provisioning profile..."

PROFILE_PLIST="$WORK_DIR/profile.plist"

security cms \
    -D \
    -i "$PROFILE_FILE" \
    > "$PROFILE_PLIST"

TEAM_ID="$(/usr/libexec/PlistBuddy \
    -c "Print :TeamIdentifier:0" \
    "$PROFILE_PLIST")"

APP_ID="$(/usr/libexec/PlistBuddy \
    -c "Print :Entitlements:application-identifier" \
    "$PROFILE_PLIST")"

BUNDLE_ID="${APP_ID#*.}"

if [ -z "$TEAM_ID" ]; then
    echo "Could not determine Team ID."
    exit 1
fi

if [ -z "$BUNDLE_ID" ]; then
    echo "Could not determine Bundle ID."
    exit 1
fi

echo "Team ID: $TEAM_ID"
echo "Bundle ID: $BUNDLE_ID"

echo "Extracting IPA..."

unzip \
    -q \
    "$INPUT_IPA" \
    -d "$WORK_DIR/payload"

APP_PATH="$(find \
    "$WORK_DIR/payload/Payload" \
    -maxdepth 1 \
    -type d \
    -name "*.app" \
    | head -n 1)"

if [ -z "$APP_PATH" ]; then
    echo "No .app found inside IPA."
    exit 1
fi

echo "Application:"
echo "$APP_PATH"

echo "Installing provisioning profile..."

cp \
    "$PROFILE_FILE" \
    "$APP_PATH/embedded.mobileprovision"

echo "Reading application entitlements..."

ENTITLEMENTS="$WORK_DIR/entitlements.plist"

codesign \
    -d \
    --entitlements :- \
    "$APP_PATH" \
    > "$ENTITLEMENTS" \
    2>/dev/null || true

echo "Finding signing identity..."

IDENTITY="$(security find-identity \
    -v \
    -p codesigning \
    "$KEYCHAIN" \
    | grep '"' \
    | head -n 1 \
    | sed -E 's/.*"([^"]+)".*/\1/')"

if [ -z "$IDENTITY" ]; then
    echo "No valid Apple signing identity found in P12."
    exit 1
fi

echo "Signing identity found."

echo "Signing embedded frameworks and dylibs..."

while IFS= read -r file; do
    codesign \
        --force \
        --sign "$IDENTITY" \
        --keychain "$KEYCHAIN" \
        "$file"
done < <(
    find "$APP_PATH" \
        \( \
            -name "*.framework" \
            -o -name "*.dylib" \
            -o -name "*.appex" \
        \) \
        -type d
)

echo "Signing application..."

if [ -s "$ENTITLEMENTS" ]; then
    codesign \
        --force \
        --sign "$IDENTITY" \
        --keychain "$KEYCHAIN" \
        --entitlements "$ENTITLEMENTS" \
        "$APP_PATH"
else
    codesign \
        --force \
        --sign "$IDENTITY" \
        --keychain "$KEYCHAIN" \
        "$APP_PATH"
fi

echo "Verifying signature..."

codesign \
    --verify \
    --deep \
    --strict \
    "$APP_PATH"

echo "Rebuilding IPA..."

(
    cd "$WORK_DIR/payload"

    zip \
        -qry \
        "$OUTPUT_IPA" \
        Payload
)

if [ ! -s "$OUTPUT_IPA" ]; then
    echo "Output IPA was not created."
    exit 1
fi

echo "IPA signing completed successfully."
