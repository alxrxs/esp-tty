cmake_minimum_required(VERSION 3.16)

# Tell wolfssl__wolfssl managed component where its own source lives.
# Its FIND_WOLFSSL_DIRECTORY only searches for dirs named "wolfssl" in
# parent directories, so it never finds managed_components/wolfssl__wolfssl.
set(WOLFSSL_ROOT "${CMAKE_SOURCE_DIR}/managed_components/wolfssl__wolfssl")

# Required by wolfSSL: use user_settings.h instead of autoconfig
# -mlongcalls: Xtensa call8 has +/-512KB range; firmware >1MB requires thunks.
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_USER_SETTINGS -mlongcalls")
set(WOLFSSL_USER_SETTINGS ON)

# Enable wolfSSH inside wolfSSL
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DESP_ENABLE_WOLFSSH -DWOLFSSL_WOLFSSH")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(esp-tty)

# Apply patches to managed_components/ AFTER idf_build_process (called inside
# project() above) has run the IDF component manager and fetched all managed
# components. The script is idempotent -- safe to call on every configure cycle.
if(EXISTS "${CMAKE_SOURCE_DIR}/patches")
    find_package(Python3 QUIET COMPONENTS Interpreter)
    if(Python3_FOUND)
        execute_process(
            COMMAND "${Python3_EXECUTABLE}"
                    "${CMAKE_SOURCE_DIR}/scripts/apply_managed_patches_cmake.py"
                    "${CMAKE_SOURCE_DIR}"
            RESULT_VARIABLE _patch_result
        )
        if(NOT _patch_result EQUAL 0)
            message(FATAL_ERROR "apply_managed_patches_cmake.py failed (exit ${_patch_result})")
        endif()
    else()
        message(WARNING "Python3 not found -- managed_components patches NOT applied")
    endif()
endif()
