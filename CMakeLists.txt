cmake_minimum_required(VERSION 3.16)

# Tell wolfssl__wolfssl managed component where its own source lives.
# Its FIND_WOLFSSL_DIRECTORY only searches for dirs named "wolfssl" in
# parent directories, so it never finds managed_components/wolfssl__wolfssl.
set(WOLFSSL_ROOT "${CMAKE_SOURCE_DIR}/managed_components/wolfssl__wolfssl")

# Required by wolfSSL: use user_settings.h instead of autoconfig
# -mlongcalls: Xtensa call8 has ±512KB range; firmware >1MB requires thunks.
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_USER_SETTINGS -mlongcalls")
set(WOLFSSL_USER_SETTINGS ON)

# Enable wolfSSH inside wolfSSL
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DESP_ENABLE_WOLFSSH -DWOLFSSL_WOLFSSH")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(esp-tty)
