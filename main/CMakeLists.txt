# -- EAP-TLS certificate embedding --------------------------------------------
# When main/certs/ca.pem, client.crt, and client.key all exist, embed them
# into the binary via EMBED_TXTFILES.  This produces linker symbols:
#   _binary_ca_pem_start / _binary_ca_pem_end
#   _binary_client_crt_start / _binary_client_crt_end
#   _binary_client_key_start / _binary_client_key_end
#
# The files must be present (real certs, not the .example stubs) for a
# WIFI_USE_ENTERPRISE build.  Copy the .example files -> real names and fill
# them in; they are gitignored.  See main/certs/README.md for details.
#
# Ordering guarantee: ESP-IDF's CMakeLists.txt is evaluated in two passes:
#   1. Script mode (-P component_get_requirements.cmake) -- dependency graph.
#   2. Project mode (normal cmake configure) -- actual build graph.
# CMAKE_CONFIGURE_DEPENDS is only valid in project mode; we guard it with
# CMAKE_SCRIPT_MODE_FILE so the CONFIGURE_DEPENDS property is registered in
# project mode only.  Once registered, CMake automatically re-runs configure
# whenever the cert files appear or disappear, so a single `pio run` always
# suffices -- no "run it twice on first build" workaround needed.
set(EAP_CERT_DIR "${CMAKE_CURRENT_LIST_DIR}/certs")
if(EXISTS "${EAP_CERT_DIR}/ca.pem" AND
   EXISTS "${EAP_CERT_DIR}/client.crt" AND
   EXISTS "${EAP_CERT_DIR}/client.key")
    set(EAP_EMBED_FILES
        "certs/ca.pem"
        "certs/client.crt"
        "certs/client.key"
    )
    message(STATUS "esp-tty: EAP-TLS cert files found -- embedding into firmware")
else()
    set(EAP_EMBED_FILES "")
endif()

# Register the EAP cert paths as configure dependencies.
if(NOT CMAKE_SCRIPT_MODE_FILE)
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
        "${EAP_CERT_DIR}/ca.pem"
        "${EAP_CERT_DIR}/client.crt"
        "${EAP_CERT_DIR}/client.key"
    )
endif()

# -- SCEP CA bundle embedding --------------------------------------------------
# When main/certs/scep_ca.pem exists, embed it into the firmware.
# This provides the TLS trust anchor for HTTPS connections to the SCEP server.
# The file must contain the full chain from the SCEP server's certificate up to
# (and including) the root CA in PEM format.
#
# To set up: copy main/certs/scep_ca.pem.example -> main/certs/scep_ca.pem
# and replace the placeholder with your actual CA certificate chain.
#
# Produces linker symbols used by scep_transport.c:
#   _binary_scep_ca_pem_start
#   _binary_scep_ca_pem_end
set(SCEP_CA_PEM "${EAP_CERT_DIR}/scep_ca.pem")
if(EXISTS "${SCEP_CA_PEM}")
    set(SCEP_EMBED_FILES "certs/scep_ca.pem")
    message(STATUS "esp-tty: SCEP CA bundle found -- embedding into firmware")
else()
    set(SCEP_EMBED_FILES "")
    message(STATUS "esp-tty: main/certs/scep_ca.pem not found -- SCEP transport disabled")
endif()

if(NOT CMAKE_SCRIPT_MODE_FILE)
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
        "${SCEP_CA_PEM}"
    )
endif()

# OTA no longer embeds any pre-shared key material.  The on-device session
# performs an ephemeral X25519 key exchange over the authenticated SSH ota@
# channel (see main/ota_session.c).  The SSH layer's OTA_AUTHORIZED_PUBKEY
# is the only OTA credential.

idf_component_register(
    SRCS
        "main.c"
        "wifi.c"
        "usb_cdc.c"
        "${CMAKE_CURRENT_LIST_DIR}/../lib/ring/ring.c"
        "${CMAKE_CURRENT_LIST_DIR}/../lib/bridge/bridge.c"
        "${CMAKE_CURRENT_LIST_DIR}/../lib/usb_cdc_drain/usb_cdc_drain.c"
        "${CMAKE_CURRENT_LIST_DIR}/../lib/term_resize/term_resize.c"
        "ssh_server.c"
        "host_key.c"
        "${CMAKE_CURRENT_LIST_DIR}/../lib/pubkey_auth/pubkey_auth.c"
        "ota_session.c"
        "${CMAKE_CURRENT_LIST_DIR}/../lib/mdns_dispatch/mdns_dispatch.c"
        "${CMAKE_CURRENT_LIST_DIR}/../lib/ssh_keepalive/ssh_keepalive.c"
        "scep_enroll.c"
        "cert_renewer.c"
        "${CMAKE_CURRENT_LIST_DIR}/../lib/cert_renewer/cert_renewer_decide.c"
        "${CMAKE_CURRENT_LIST_DIR}/../lib/util/zeroize.c"
        "${CMAKE_CURRENT_LIST_DIR}/../lib/scep_proto/scep_proto.c"
        "${CMAKE_CURRENT_LIST_DIR}/../lib/cred_store/cred_store.c"
        "${CMAKE_CURRENT_LIST_DIR}/../lib/scep_transport/scep_transport.c"
    INCLUDE_DIRS
        "."
        "${CMAKE_CURRENT_LIST_DIR}/../lib/ring"
        "${CMAKE_CURRENT_LIST_DIR}/../lib/bridge"
        "${CMAKE_CURRENT_LIST_DIR}/../lib/usb_cdc_drain"
        "${CMAKE_CURRENT_LIST_DIR}/../lib/term_resize"
        "${CMAKE_CURRENT_LIST_DIR}/../lib/pubkey_auth"
        "${CMAKE_CURRENT_LIST_DIR}/../lib/mdns_dispatch"
        "${CMAKE_CURRENT_LIST_DIR}/../lib/ssh_keepalive"
        "${CMAKE_CURRENT_LIST_DIR}/../lib/cred_store"
        "${CMAKE_CURRENT_LIST_DIR}/../lib/scep_transport"
        "${CMAKE_CURRENT_LIST_DIR}/../lib/scep_proto"
        "${CMAKE_CURRENT_LIST_DIR}/../lib/cert_renewer"
        "${CMAKE_CURRENT_LIST_DIR}/../lib/util"
    REQUIRES
        wolfssl
        wolfssl__wolfssh
        wpa_supplicant     # exposes esp_eap_client.h for WPA2/WPA3-Enterprise
        app_update         # esp_ota_ops.h
        nvs_flash          # cred_store NVS backend
        esp_http_client    # scep_transport HTTPS
        mbedtls            # TLS backing for esp_http_client
    EMBED_TXTFILES
        ${EAP_EMBED_FILES}
        ${SCEP_EMBED_FILES}
)
