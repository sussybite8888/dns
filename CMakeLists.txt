cmake_minimum_required(VERSION 3.15)
project(dns-server-cpp VERSION 1.0.0 LANGUAGES CXX)

# Option for admin password (set at build time)
# Default password is "password" if not specified
if(NOT DEFINED ADMIN_PASSWORD)
    set(ADMIN_PASSWORD "password" CACHE STRING "Password for the domain overrides editor")
elseif(ADMIN_PASSWORD STREQUAL "" OR ADMIN_PASSWORD STREQUAL "OFF")
    set(ADMIN_PASSWORD "password" CACHE STRING "Password for the domain overrides editor" FORCE)
endif()

# Build-time option to enable DNS IP whitelist enforcement
option(ENABLE_DNS_WHITELIST "Enable DNS client IP whitelist enforcement" OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Enable parallel builds
include(ProcessorCount)
ProcessorCount(N)
if(NOT N EQUAL 0)
    set(CMAKE_BUILD_PARALLEL_LEVEL ${N})
    message(STATUS "Using ${N} parallel build jobs")
endif()

# Use ccache if available for faster rebuilds
find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
    set(CMAKE_CXX_COMPILER_LAUNCHER ${CCACHE_PROGRAM})
    message(STATUS "Using ccache for faster compilation")
endif()

# Find required packages
find_package(Threads REQUIRED)

# Source files
set(SOURCES
    cpp/src/main.cpp
    cpp/src/DnsServer.cpp
    cpp/src/DnsPacket.cpp
    cpp/src/Moderation.cpp
)

# Create executable
add_executable(dns-server ${SOURCES})

# macOS: package Release builds as an app bundle (dns-server.app).
# Debug/RelWithDebInfo builds stay a plain CLI binary for easy local use.
if(APPLE AND CMAKE_BUILD_TYPE STREQUAL "Release")
    set_target_properties(dns-server PROPERTIES
        MACOSX_BUNDLE TRUE
        MACOSX_BUNDLE_BUNDLE_NAME "DNS Server"
        MACOSX_BUNDLE_GUI_IDENTIFIER "local.dns-server"
        MACOSX_BUNDLE_BUNDLE_VERSION "${PROJECT_VERSION}"
        MACOSX_BUNDLE_SHORT_VERSION_STRING "${PROJECT_VERSION}"
        # Custom template adds LSBackgroundOnly so the server runs as a
        # background process (no Dock icon or launch animation)
        MACOSX_BUNDLE_INFO_PLIST "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Info.plist.in"
    )
    message(STATUS "macOS Release build: packaging as dns-server.app bundle")

    # Ship the web UI inside the bundle; the server extracts it to its data
    # directory on first launch. Must run before the codesign step below,
    # since bundle resources are part of the signature seal.
    add_custom_command(TARGET dns-server POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${CMAKE_CURRENT_SOURCE_DIR}/cpp/web
            $<TARGET_BUNDLE_DIR:dns-server>/Contents/Resources/web
        COMMENT "Copying web UI into dns-server.app resources"
    )

    # Embed dylib dependencies (OpenSSL, brotli, ...) so the bundle is
    # self-contained, then re-sign. Runs after every (re)link of the binary.
    add_custom_command(TARGET dns-server POST_BUILD
        COMMAND ${CMAKE_COMMAND}
            -DBUNDLE_PATH=$<TARGET_BUNDLE_DIR:dns-server>
            -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/FixupBundle.cmake
        COMMENT "Embedding dylib dependencies into dns-server.app"
    )
endif()

# Use modern include directories (faster than global include_directories)
target_include_directories(dns-server PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/cpp/src)

# Link libraries
target_link_libraries(dns-server 
    PRIVATE 
    Threads::Threads
    ${CMAKE_DL_LIBS}
)

# JSON library (nlohmann/json - header-only)
# Use EXCLUDE_FROM_ALL to speed up initial configuration
include(FetchContent)
FetchContent_Declare(
    json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.2
)
FetchContent_MakeAvailable(json)
target_link_libraries(dns-server PRIVATE nlohmann_json::nlohmann_json)

# HTTP server library (cpp-httplib)
FetchContent_Declare(
    httplib
    GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
    GIT_TAG v0.14.3
)
FetchContent_MakeAvailable(httplib)
target_link_libraries(dns-server PRIVATE httplib::httplib)

# OpenSSL (optional) - enables the native DNS-over-HTTPS (TLS) server.
# Without it, DoH is still served over plain HTTP at /dns-query
# (e.g. behind a TLS-terminating reverse proxy).
find_package(OpenSSL)
if(OPENSSL_FOUND)
    target_compile_definitions(dns-server PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)
    target_link_libraries(dns-server PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    message(STATUS "OpenSSL found - native DoH (HTTPS) server enabled")
else()
    message(STATUS "OpenSSL not found - DoH available over plain HTTP only (/dns-query)")
endif()

# Compiler-specific options
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    # Use faster compilation flags in Debug mode
    target_compile_options(dns-server PRIVATE 
        $<$<CONFIG:Debug>:-Wall -Wextra -O0 -g>
        $<$<CONFIG:Release>:-Wall -Wextra -pedantic -O3>
        $<$<CONFIG:RelWithDebInfo>:-Wall -Wextra -O2 -g>
    )
    
    # Enable faster template instantiation
    target_compile_options(dns-server PRIVATE -ftemplate-backtrace-limit=0)
endif()

# Generate compile_commands.json for better IDE support and faster incremental builds
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Pass admin password to the code
target_compile_definitions(dns-server PRIVATE ADMIN_PASSWORD="${ADMIN_PASSWORD}")
message(STATUS "Admin password protection enabled (password: ${ADMIN_PASSWORD})")

if(ENABLE_DNS_WHITELIST)
    target_compile_definitions(dns-server PRIVATE ENABLE_DNS_WHITELIST=1)
    message(STATUS "DNS whitelist enforcement: ENABLED")
else()
    target_compile_definitions(dns-server PRIVATE ENABLE_DNS_WHITELIST=0)
    message(STATUS "DNS whitelist enforcement: DISABLED")
endif()

# Installation (BUNDLE covers macOS Release .app builds, RUNTIME the plain binary)
install(TARGETS dns-server
    BUNDLE DESTINATION .
    RUNTIME DESTINATION bin)

