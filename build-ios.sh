#!/bin/bash
#
# Build the iOS app and package it as build-ios/dns-server.ipa.
#
# Requires macOS with Xcode (not just the Command Line Tools) installed.
#
# Usage: ./build-ios.sh [Debug|Release] [--simulator]
#
# By default this produces an UNSIGNED .ipa, which cannot be installed by
# double-clicking: re-sign it with your own certificate (Xcode, Sideloadly,
# AltStore, ...) first. To sign during the build instead, export your Apple
# Developer team ID:
#
#   IOS_DEVELOPMENT_TEAM=ABCDE12345 ./build-ios.sh

set -e

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

CONFIG="Release"
SDK="iphoneos"
BUILD_DIR="build-ios"

for arg in "$@"; do
    case "$arg" in
        Debug|Release) CONFIG="$arg" ;;
        --simulator)   SDK="iphonesimulator"; BUILD_DIR="build-ios-sim" ;;
        *)
            echo "Usage: $0 [Debug|Release] [--simulator]" >&2
            exit 1
            ;;
    esac
done

if [[ "$(uname)" != "Darwin" ]]; then
    echo "error: iOS builds require macOS" >&2
    exit 1
fi

if ! xcodebuild -version >/dev/null 2>&1; then
    echo "error: full Xcode is required (xcode-select -s /Applications/Xcode.app)" >&2
    exit 1
fi

CMAKE_ARGS=(
    -B "$BUILD_DIR"
    -G Xcode
    -DCMAKE_SYSTEM_NAME=iOS
    -DCMAKE_OSX_SYSROOT="$SDK"
    -DCMAKE_OSX_DEPLOYMENT_TARGET=15.0
)

if [[ -n "$IOS_DEVELOPMENT_TEAM" ]]; then
    echo "Signing with development team $IOS_DEVELOPMENT_TEAM"
    CMAKE_ARGS+=(-DCMAKE_XCODE_ATTRIBUTE_DEVELOPMENT_TEAM="$IOS_DEVELOPMENT_TEAM")
else
    echo "No IOS_DEVELOPMENT_TEAM set - producing an unsigned build"
    CMAKE_ARGS+=(
        -DCMAKE_XCODE_ATTRIBUTE_CODE_SIGNING_ALLOWED=NO
        -DCMAKE_XCODE_ATTRIBUTE_CODE_SIGNING_REQUIRED=NO
        -DCMAKE_XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY=""
    )
fi

echo "Configuring iOS build ($CONFIG, $SDK)..."
cmake -S "$ROOT" "${CMAKE_ARGS[@]}"

# The simulator cannot install .ipa files, so only build the .app there.
TARGET="ipa"
if [[ "$SDK" == "iphonesimulator" ]]; then
    TARGET="dns-server"
fi

echo "Building target '$TARGET'..."
cmake --build "$BUILD_DIR" --config "$CONFIG" --target "$TARGET"

echo ""
if [[ "$TARGET" == "ipa" ]]; then
    echo "Build complete: $BUILD_DIR/dns-server.ipa"
    ls -lh "$BUILD_DIR/dns-server.ipa"
    if [[ -z "$IOS_DEVELOPMENT_TEAM" ]]; then
        echo ""
        echo "This .ipa is unsigned - re-sign it before installing on a device."
    fi
else
    echo "Build complete: $BUILD_DIR/$CONFIG-$SDK/dns-server.app"
    echo "Install with: xcrun simctl install booted '$BUILD_DIR/$CONFIG-$SDK/dns-server.app'"
fi
echo ""
echo "Note: iOS apps cannot bind privileged ports, so DNS listens on 5300"
echo "(not 53) and the web UI on 4167."
