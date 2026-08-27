# Run with: cmake -DBUNDLE_PATH=<path to .app> -P FixupBundle.cmake
#
# Copies non-system dylib dependencies (Homebrew OpenSSL, brotli, ...) into
# the app bundle and rewrites install names so the bundle runs on machines
# without those libraries installed.
include(BundleUtilities)
set(BU_CHMOD_BUNDLE_ITEMS ON)
fixup_bundle("${BUNDLE_PATH}" "" "")

# install_name_tool invalidates code signatures, and unsigned binaries won't
# load on Apple Silicon - ad-hoc re-sign the embedded libraries and the app.
file(GLOB_RECURSE embedded_libs "${BUNDLE_PATH}/Contents/*.dylib")
foreach(lib IN LISTS embedded_libs)
    execute_process(COMMAND codesign --force --sign - "${lib}" RESULT_VARIABLE sign_result)
    if(NOT sign_result EQUAL 0)
        message(FATAL_ERROR "codesign failed for ${lib}")
    endif()
endforeach()
execute_process(COMMAND codesign --force --sign - "${BUNDLE_PATH}" RESULT_VARIABLE sign_result)
if(NOT sign_result EQUAL 0)
    message(FATAL_ERROR "codesign failed for ${BUNDLE_PATH}")
endif()
