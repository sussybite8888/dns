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

