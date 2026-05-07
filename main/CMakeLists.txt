# ── EAP-TLS certificate embedding ────────────────────────────────────────────
# When main/certs/ca.pem, client.crt, and client.key all exist, embed them
# into the binary via EMBED_TXTFILES.  This produces linker symbols:
#   _binary_ca_pem_start / _binary_ca_pem_end
#   _binary_client_crt_start / _binary_client_crt_end
#   _binary_client_key_start / _binary_client_key_end
#
# The files must be present (real certs, not the .example stubs) for a
# WIFI_USE_ENTERPRISE build.  Copy the .example files → real names and fill
# them in; they are gitignored.  See main/certs/README.md for details.
#
# Ordering guarantee: ESP-IDF's CMakeLists.txt is evaluated in two passes:
#   1. Script mode (-P component_get_requirements.cmake) — dependency graph.
#   2. Project mode (normal cmake configure) — actual build graph.
# CMAKE_CONFIGURE_DEPENDS is only valid in project mode; we guard it with
# CMAKE_SCRIPT_MODE_FILE so the CONFIGURE_DEPENDS property is registered in
# project mode only.  Once registered, CMake automatically re-runs configure
# whenever the cert files appear or disappear, so a single `pio run` always
# suffices — no "run it twice on first build" workaround needed.
set(EAP_CERT_DIR "${CMAKE_CURRENT_LIST_DIR}/certs")
if(EXISTS "${EAP_CERT_DIR}/ca.pem" AND
   EXISTS "${EAP_CERT_DIR}/client.crt" AND
   EXISTS "${EAP_CERT_DIR}/client.key")
    set(EAP_EMBED_FILES
        "certs/ca.pem"
        "certs/client.crt"
        "certs/client.key"
    )
    message(STATUS "esp-tty: EAP-TLS cert files found — embedding into firmware")
else()
    set(EAP_EMBED_FILES "")
endif()

# Register the cert paths as configure dependencies so CMake re-runs when
# certs are added or removed (project-mode only; CONFIGURE_DEPENDS is invalid
# in ESP-IDF's script-mode requirement pass).
if(NOT CMAKE_SCRIPT_MODE_FILE)
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
        "${EAP_CERT_DIR}/ca.pem"
        "${EAP_CERT_DIR}/client.crt"
        "${EAP_CERT_DIR}/client.key"
    )
endif()

idf_component_register(
    SRCS
        "main.c"
        "wifi.c"
        "usb_cdc.c"
        "${CMAKE_CURRENT_LIST_DIR}/../lib/ring/ring.c"
        "${CMAKE_CURRENT_LIST_DIR}/../lib/bridge/bridge.c"
        "ssh_server.c"
        "host_key.c"
        "${CMAKE_CURRENT_LIST_DIR}/../lib/pubkey_auth/pubkey_auth.c"
    INCLUDE_DIRS
        "."
        "${CMAKE_CURRENT_LIST_DIR}/../lib/ring"
        "${CMAKE_CURRENT_LIST_DIR}/../lib/bridge"
        "${CMAKE_CURRENT_LIST_DIR}/../lib/pubkey_auth"
    REQUIRES
        wolfssl
        wolfssl__wolfssh
        wpa_supplicant     # exposes esp_eap_client.h for WPA2/WPA3-Enterprise
    EMBED_TXTFILES
        ${EAP_EMBED_FILES}
)
