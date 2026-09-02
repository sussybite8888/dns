cmake_minimum_required(VERSION 3.15)
project(dns-server-cpp VERSION 1.0.0 LANGUAGES CXX)

# iOS builds are selected with -DCMAKE_SYSTEM_NAME=iOS (see build-ios.sh).
# CMake then sets both APPLE and IOS, so the macOS-only branches below have to
# exclude IOS explicitly.
if(IOS)
    # The iOS host app (cpp/ios/main_ios.mm) is Objective-C++
    enable_language(OBJCXX)
    set(CMAKE_OBJCXX_STANDARD 17)
    set(CMAKE_OBJCXX_STANDARD_REQUIRED ON)
endif()

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
    cpp/src/DnsServer.cpp
    cpp/src/DnsPacket.cpp
    cpp/src/Moderation.cpp
)

if(IOS)
    # iOS has no console and terminates apps that never present a UI, so the
    # command-line entry point is replaced by a UIKit host that runs the server
    # on a background thread and shows the web UI in a WKWebView.
    list(APPEND SOURCES cpp/ios/main_ios.mm)
else()
    list(APPEND SOURCES cpp/src/main.cpp)
endif()

if(WIN32)
    # Embeds assets/icons/windows/app_icon.ico into dns-server.exe so Explorer,
    # the taskbar and Alt-Tab show the app icon.
    enable_language(RC)
    list(APPEND SOURCES cmake/app_icon.rc)
endif()

# Create executable
add_executable(dns-server ${SOURCES})

# macOS: package Release builds as an app bundle (dns-server.app).
# Debug/RelWithDebInfo builds stay a plain CLI binary for easy local use.
if(APPLE AND NOT IOS AND CMAKE_BUILD_TYPE STREQUAL "Release")
    set_target_properties(dns-server PROPERTIES
        MACOSX_BUNDLE TRUE
        MACOSX_BUNDLE_BUNDLE_NAME "DNS Server"
        MACOSX_BUNDLE_GUI_IDENTIFIER "local.dns-server"
        MACOSX_BUNDLE_BUNDLE_VERSION "${PROJECT_VERSION}"
        MACOSX_BUNDLE_SHORT_VERSION_STRING "${PROJECT_VERSION}"
        # Custom template adds LSBackgroundOnly so the server runs as a
        # background process (no Dock icon or launch animation)
        MACOSX_BUNDLE_INFO_PLIST "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Info.plist.in"
        MACOSX_BUNDLE_ICON_FILE "AppIcon.icns"
    )
    message(STATUS "macOS Release build: packaging as dns-server.app bundle")

    # App icon. LSBackgroundOnly keeps the app out of the Dock, so this is what
    # Finder and Get Info show. Added as a bundle resource rather than copied in
    # POST_BUILD so it is in place before the codesign step seals the bundle.
    set(MACOS_ICON "${CMAKE_CURRENT_SOURCE_DIR}/assets/icons/macos/AppIcon.icns")
    set_source_files_properties(${MACOS_ICON} PROPERTIES MACOSX_PACKAGE_LOCATION "Resources")
    target_sources(dns-server PRIVATE ${MACOS_ICON})

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

# iOS: build dns-server.app and package it as an .ipa.
if(IOS)
    set_target_properties(dns-server PROPERTIES
        MACOSX_BUNDLE TRUE
        MACOSX_BUNDLE_BUNDLE_NAME "DNS Server"
        MACOSX_BUNDLE_GUI_IDENTIFIER "local.dns-server"
        MACOSX_BUNDLE_BUNDLE_VERSION "${PROJECT_VERSION}"
        MACOSX_BUNDLE_SHORT_VERSION_STRING "${PROJECT_VERSION}"
        MACOSX_BUNDLE_INFO_PLIST "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Info.plist.ios.in"
        XCODE_ATTRIBUTE_PRODUCT_BUNDLE_IDENTIFIER "local.dns-server"
        # iPhone + iPad. Xcode writes UIDeviceFamily from this setting and
        # warns if the plist template tries to supply the key itself.
        XCODE_ATTRIBUTE_TARGETED_DEVICE_FAMILY "1,2"
    )

    # main_ios.mm relies on ARC, which CMake's Xcode generator leaves off.
    # Set both the Xcode setting and the raw flag so a Ninja/Makefile
    # configuration of the same tree behaves identically.
    set_target_properties(dns-server PROPERTIES XCODE_ATTRIBUTE_CLANG_ENABLE_OBJC_ARC YES)
    target_compile_options(dns-server PRIVATE $<$<COMPILE_LANGUAGE:OBJCXX>:-fobjc-arc>)

    target_link_libraries(dns-server PRIVATE
        "-framework UIKit"
        "-framework WebKit"
        "-framework Foundation"
        "-framework CoreGraphics"
    )

    # App icons. Plain PNGs listed under CFBundleIcons in the plist template,
    # not a compiled .xcassets: actool needs an installed simulator runtime,
    # so an asset catalog would break device-only build machines and CI.
    # AppIcon-1024 is the App Store marketing size and is not bundled.
    set(IOS_ICONS "")
    foreach(size IN ITEMS 20 29 40 58 60 76 80 87 120 152 167 180)
        list(APPEND IOS_ICONS "${CMAKE_CURRENT_SOURCE_DIR}/assets/icons/ios/AppIcon-${size}.png")
    endforeach()
    set_source_files_properties(${IOS_ICONS} PROPERTIES MACOSX_PACKAGE_LOCATION "Resources")
    target_sources(dns-server PRIVATE ${IOS_ICONS})

    # iOS bundles are flat, so resources sit directly in dns-server.app/.
    # main_ios.mm copies web/index.html out to Documents/ on launch.
    add_custom_command(TARGET dns-server POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${CMAKE_CURRENT_SOURCE_DIR}/cpp/web
            $<TARGET_BUNDLE_CONTENT_DIR:dns-server>/web
        COMMENT "Copying web UI into dns-server.app resources"
    )

    # An .ipa is just a zip of Payload/<name>.app. Build it with:
    #   cmake --build <dir> --config Release --target ipa
    set(IPA_STAGE "${CMAKE_BINARY_DIR}/ipa-stage")
    set(IPA_FILE "${CMAKE_BINARY_DIR}/dns-server.ipa")
    add_custom_target(ipa
        COMMAND ${CMAKE_COMMAND} -E rm -rf "${IPA_STAGE}" "${IPA_FILE}"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${IPA_STAGE}/Payload"
        # ditto rather than cmake -E copy_directory: it preserves the executable
        # bit, symlinks and extended attributes that make the bundle installable
        COMMAND ditto "$<TARGET_BUNDLE_DIR:dns-server>" "${IPA_STAGE}/Payload/dns-server.app"
        COMMAND ${CMAKE_COMMAND} -E chdir "${IPA_STAGE}" zip -qry "${IPA_FILE}" Payload
        COMMAND ${CMAKE_COMMAND} -E rm -rf "${IPA_STAGE}"
        COMMAND ${CMAKE_COMMAND} -E echo "Wrote ${IPA_FILE}"
        COMMENT "Packaging dns-server.ipa"
        # No VERBATIM: with the Xcode generator the bundle path contains a
        # literal ${EFFECTIVE_PLATFORM_NAME}, which the run-script phase's
        # shell has to expand. Quoting it would break the copy.
        USES_TERMINAL
    )
    add_dependencies(ipa dns-server)
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

# Show clone/download progress during the first configure; without this the
# dependency downloads are silent and the configure step looks stuck.
set(FETCHCONTENT_QUIET FALSE)

# Release archives rather than git clones: the nlohmann/json repository is
# ~170MB of history and test data, while its release archive is ~107KB.
FetchContent_Declare(
    json
    URL https://github.com/nlohmann/json/releases/download/v3.11.2/json.tar.xz
    URL_HASH SHA256=8c4b26bf4b422252e13f332bc5e388ec0ab5c3443d24399acb675e68278d341f
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(json)
target_link_libraries(dns-server PRIVATE nlohmann_json::nlohmann_json)

# HTTP server library (cpp-httplib)
FetchContent_Declare(
    httplib
    URL https://github.com/yhirose/cpp-httplib/archive/refs/tags/v0.14.3.tar.gz
    URL_HASH SHA256=dcf6486d9030937636d8a4f820ca9531808fd7edb283893dddbaa05f99357e63
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(httplib)
target_link_libraries(dns-server PRIVATE httplib::httplib)

# OpenSSL (optional) - enables the native DNS-over-HTTPS (TLS) server.
# Without it, DoH is still served over plain HTTP at /dns-query
# (e.g. behind a TLS-terminating reverse proxy).
# Skipped on iOS: there is no system OpenSSL in the SDK, and probing would
# otherwise pick up the host's Homebrew build and fail at link time.
if(NOT IOS)
    find_package(OpenSSL)
endif()
if(OPENSSL_FOUND)
    target_compile_definitions(dns-server PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)
    target_link_libraries(dns-server PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    message(STATUS "OpenSSL found - native DoH (HTTPS) server enabled")
else()
    message(STATUS "OpenSSL not available - DoH served over plain HTTP only (/dns-query)")
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

