# Bridge component: provides the 'wolfssl' IDF component name that
# wolfssl__wolfssh expects via REQUIRES. Compiles wolfssl source directly
# since wolfssl__wolfssl's FIND_WOLFSSL_DIRECTORY never locates managed_components/.
set(WOLFSSL_MC "${CMAKE_CURRENT_LIST_DIR}/../../managed_components/wolfssl__wolfssl")

file(GLOB WOLFSSL_SRCS
    "${WOLFSSL_MC}/src/*.c"
    "${WOLFSSL_MC}/wolfcrypt/src/*.c"
    "${WOLFSSL_MC}/wolfcrypt/src/port/Espressif/*.c"
)

# Mirror wolfssl__wolfssl's COMPONENT_SRCEXCLUDE list + diagnostics file
list(REMOVE_ITEM WOLFSSL_SRCS
    "${WOLFSSL_MC}/src/bio.c"
    "${WOLFSSL_MC}/src/conf.c"
    "${WOLFSSL_MC}/src/misc.c"
    "${WOLFSSL_MC}/src/pk.c"
    "${WOLFSSL_MC}/src/ssl_asn1.c"
    "${WOLFSSL_MC}/src/ssl_bn.c"
    "${WOLFSSL_MC}/src/ssl_certman.c"
    "${WOLFSSL_MC}/src/ssl_crypto.c"
    "${WOLFSSL_MC}/src/ssl_load.c"
    "${WOLFSSL_MC}/src/ssl_misc.c"
    "${WOLFSSL_MC}/src/ssl_p7p12.c"
    "${WOLFSSL_MC}/src/ssl_sess.c"
    "${WOLFSSL_MC}/src/x509.c"
    "${WOLFSSL_MC}/src/x509_str.c"
    "${WOLFSSL_MC}/wolfcrypt/src/ext_kyber.c"
    "${WOLFSSL_MC}/wolfcrypt/src/evp.c"
    "${WOLFSSL_MC}/wolfcrypt/src/misc.c"
    "${WOLFSSL_MC}/wolfcrypt/src/sp_sm2_arm32.c"
    "${WOLFSSL_MC}/wolfcrypt/src/sp_sm2_arm64.c"
    "${WOLFSSL_MC}/wolfcrypt/src/sp_sm2_armthumb.c"
    "${WOLFSSL_MC}/wolfcrypt/src/sp_sm2_c32.c"
    "${WOLFSSL_MC}/wolfcrypt/src/sp_sm2_c64.c"
    "${WOLFSSL_MC}/wolfcrypt/src/sp_sm2_cortexm.c"
    "${WOLFSSL_MC}/wolfcrypt/src/sp_sm2_x86_64.c"
    # Diagnostic utility -- uses linker section symbols as C variables; also uses
    # `thread_local` as an enum value name which conflicts with the C11 keyword.
    "${WOLFSSL_MC}/wolfcrypt/src/port/Espressif/esp_sdk_mem_lib.c"
    # esp32_aes.c and esp32_sha.c are now compiled with IDF 6 HAL support.
    # patches/wolfssl__wolfssl/0002-adapt-esp32-aes-sha-to-idf6-periph-clock-api.patch
    # replaced PERIPH_AES_MODULE/PERIPH_SHA_MODULE with esp_crypto_aes/sha_enable_periph_clk().
)

# Remove Xtensa assembly files -- not valid for this toolchain invocation
file(GLOB WOLFSSL_ASM "${WOLFSSL_MC}/wolfcrypt/src/*.S")
if(WOLFSSL_ASM)
    list(REMOVE_ITEM WOLFSSL_SRCS ${WOLFSSL_ASM})
endif()

idf_component_register(
    SRCS ${WOLFSSL_SRCS}
    INCLUDE_DIRS
        "include"
        "${WOLFSSL_MC}"
        "${WOLFSSL_MC}/wolfssl"
        "${WOLFSSL_MC}/wolfssl/wolfcrypt"
        "${WOLFSSL_MC}/wolfssl/wolfcrypt/port/Espressif"
    PRIV_REQUIRES esp_hw_support esp_security
)
