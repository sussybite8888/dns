# Building the DNS Server

## Quick Build

### Release Build (Default)
```bash
./build.sh
# or
./build.sh Release
```

### Debug Build
```bash
./build.sh Debug
```

### Release with Debug Symbols
```bash
./build.sh RelWithDebInfo
```

### iOS (.ipa)
```bash
./build-ios.sh              # Release, device (arm64) -> build-ios/dns-server.ipa
./build-ios.sh Debug
./build-ios.sh --simulator  # builds the .app only; the simulator cannot install .ipa files
```

Requires macOS with full Xcode installed (`xcode-select -s /Applications/Xcode.app`),
not just the Command Line Tools.

By default the build is **unsigned**, so the `.ipa` cannot be installed by
double-clicking - re-sign it with your own certificate (Xcode, Sideloadly,
AltStore, ...) first. To sign during the build, export your Apple Developer
team ID:

```bash
IOS_DEVELOPMENT_TEAM=ABCDE12345 ./build-ios.sh
```

Two things work differently on iOS, both forced by the platform:

- **DNS listens on port 5300, not 53.** App Store sandboxed apps run without
  root and cannot bind privileged ports. Point clients at port 5300 explicitly;
  iOS itself cannot be configured to use a custom DNS port, so the device
  serves other machines on the network rather than itself.
- **The app must stay in the foreground.** iOS suspends backgrounded apps, which
  stops the server. There is no background mode that legitimately covers a
  long-running listening socket.

The app (`cpp/ios/main_ios.mm`) replaces the command-line entry point with a
UIKit host: it runs `DnsServer` on a background thread and shows the same web
UI in a `WKWebView` pointed at `http://127.0.0.1:4167/`.

## Manual Build

### Debug Build
```bash
mkdir -p build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
```

### Release Build
```bash
mkdir -p build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
```

### iOS Build
```bash
cmake -S . -B build-ios -G Xcode \
    -DCMAKE_SYSTEM_NAME=iOS \
    -DCMAKE_OSX_SYSROOT=iphoneos \
    -DCMAKE_OSX_DEPLOYMENT_TARGET=15.0 \
    -DCMAKE_XCODE_ATTRIBUTE_CODE_SIGNING_ALLOWED=NO
cmake --build build-ios --config Release --target ipa
```

The `ipa` target builds `dns-server.app` and repackages it as
`build-ios/dns-server.ipa` (an `.ipa` is just a zip of `Payload/<name>.app`).
Building the default target instead produces only the `.app`.

## App Icons

`app_icon.png` in the repository root is the single source for every platform's
icon. The per-platform files under `assets/icons/` are committed, so a normal
build needs no extra tooling; re-run the generator only after changing
`app_icon.png`:

```bash
./scripts/generate-icons.sh   # macOS only (uses sips and iconutil)
```

| Platform | Generated file | How it is used |
| --- | --- | --- |
| macOS | `assets/icons/macos/AppIcon.icns` | Copied into `dns-server.app/Contents/Resources`, referenced by `CFBundleIconFile`. `LSBackgroundOnly` keeps the app out of the Dock, so this is the Finder icon. |
| Windows | `assets/icons/windows/app_icon.ico` | Embedded in `dns-server.exe` through `cmake/app_icon.rc`, so Explorer, the taskbar and Alt-Tab show it. |
| iOS | `assets/icons/ios/AppIcon-*.png` | Copied into the app bundle and listed under `CFBundleIcons` in `cmake/Info.plist.ios.in`. |

The Windows wiring is in place but currently untested end to end: the server
sources use BSD sockets (`sys/socket.h`, `netinet/in.h`, `unistd.h`) and have no
Winsock port yet, so `dns-server.exe` does not build. `cmake/app_icon.rc` is
added to the sources under `if(WIN32)` and will embed the icon as soon as that
port exists.

Plain PNGs are used for iOS rather than a compiled `.xcassets`, because `actool`
requires an installed simulator runtime and would break device-only build
machines and CI. `AppIcon-1024.png` is generated for App Store submission but is
not bundled; submitting to the App Store would need an asset catalog.

Note that `app_icon.png` is 225x225, so the larger sizes (512, 1024) are
upscaled. Replacing it with a 1024x1024 original and re-running the generator
will produce sharper icons at no other cost.

## Build Types

- **Debug**: No optimization (`-O0`), includes debug symbols (`-g`), fastest compilation
- **Release**: Full optimization (`-O3`), no debug symbols, best performance
- **RelWithDebInfo**: Optimized (`-O2`) with debug symbols, good for production debugging

## Debugging

### Using GDB (Linux)
```bash
cd build
gdb ./dns-server
```

### Using LLDB (macOS)
```bash
cd build
lldb ./dns-server
```

### Running with Debugger
```bash
# Set breakpoints, then run
sudo lldb ./dns-server
(lldb) break DnsServer::handleDnsQuery
(lldb) run
```

## Build Optimizations

The build system automatically:
- Uses all available CPU cores for parallel compilation
- Uses ccache if available for faster rebuilds
- Generates `compile_commands.json` for IDE support
- Optimizes compiler flags based on build type

