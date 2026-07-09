#!/bin/bash

# Build script for DNS Server C++

set -e

# Parse build type argument
BUILD_TYPE="${1:-Release}"

if [[ "$BUILD_TYPE" != "Debug" && "$BUILD_TYPE" != "Release" && "$BUILD_TYPE" != "RelWithDebInfo" ]]; then
    echo "Usage: $0 [Debug|Release|RelWithDebInfo]"
    echo "  Debug         - Debug build with symbols, no optimization"
    echo "  Release       - Optimized release build (default)"
    echo "  RelWithDebInfo - Optimized build with debug symbols"
    exit 1
fi

echo "Building DNS Server (C++) in $BUILD_TYPE mode..."

# Create build directory
mkdir -p build
cd build

# Configure with CMake
cmake .. -DCMAKE_BUILD_TYPE=$BUILD_TYPE

# Build with parallel jobs
JOBS=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
echo "Building with $JOBS parallel jobs..."
make -j$JOBS

echo ""
echo "Build complete! Executable: build/dns-server"
echo "Build type: $BUILD_TYPE"
echo ""
echo "To run (requires sudo for port 53):"
echo "  sudo ./build/dns-server"
echo ""
if [[ "$BUILD_TYPE" == "Debug" ]]; then
    echo "Debug build includes symbols for debugging with gdb/lldb"
fi

