/*
 * ssh_server.c — wolfSSH server: accept loop, auth, bidirectional bridge
 *
 * Architecture:
 *   ssh_server_task (one FreeRTOS task, portMAX_DELAY on accept)
 *     → per-session: two bridge tasks (ssh_to_usb, usb_to_ssh)
 *
 * Single-session takeover: when a second client connects while one is active,
 * the old session is torn down and the new one takes over.
 */

#include "ssh_server.h"
#include "host_key.h"
#include "pubkey_auth.h"
#include "bridge.h"
#include "ota_session.h"
#include "config.h"   /* SSH_PORT, AUTHORIZED_PUBKEY, OTA_AUTHORIZED_PUBKEY */

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/time.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssh/ssh.h"

static const char *TAG = "ssh_server";

/* ------------------------------------------------------------------ */
/* Module state                                                        */

static WOLFSSH_CTX  *s_ctx         = NULL;
static ring_t       *s_usb_to_ssh  = NULL;
static ring_t       *s_ssh_to_usb  = NULL;

/* Active session (protected by s_session_mutex) */
static SemaphoreHandle_t s_session_mutex;
static WOLFSSH      *s_active_ssh  = NULL;
static int           s_active_fd   = -1;
static volatile bool s_pump_stop   = false;

/* Precomputed SHA-256 of the authorized public key blob.
   Populated at startup from AUTHORIZED_PUBKEY in config.h. */
static uint8_t s_authkey_hash[PUBKEY_HASH_SIZE];
static bool    s_authkey_hash_ready = false;

/* Precomputed SHA-256 of the OTA authorized public key blob.
   Populated at startup from OTA_AUTHORIZED_PUBKEY in config.h. */
static uint8_t s_ota_authkey_hash[PUBKEY_HASH_SIZE];
static bool    s_ota_authkey_hash_ready = false;

/* ------------------------------------------------------------------ */
/* wolfSSH user auth callback                                          */
/* ------------------------------------------------------------------ */

static int user_auth_callback(byte authType, WS_UserAuthData *authData,
                              void *ctx)
{
    (void)ctx;

    if (authType != WOLFSSH_USERAUTH_PUBLICKEY)
        return WOLFSSH_USERAUTH_FAILURE;

    if (!s_authkey_hash_ready)
        return WOLFSSH_USERAUTH_FAILURE;

    /* Determine which key hash to check based on the username */
    const uint8_t *expected_hash = s_authkey_hash;
    bool is_ota_user = false;

    if (authData->username && authData->usernameSz >= 3 &&
        strncmp((const char *)authData->username, "ota", authData->usernameSz) == 0) {
        if (!s_ota_authkey_hash_ready) {
            ESP_LOGW(TAG, "OTA auth attempted but OTA key not configured");
            return WOLFSSH_USERAUTH_FAILURE;
        }
        expected_hash = s_ota_authkey_hash;
        is_ota_user   = true;
    }

    pubkey_auth_result_t res = pubkey_auth_check(
        authData->sf.publicKey.publicKey,
        authData->sf.publicKey.publicKeySz,
        expected_hash);

    if (res != PUBKEY_AUTH_OK) {
        ESP_LOGW(TAG, "Auth rejected: unknown public key (user=%.*s)",
                 (int)authData->usernameSz, (const char *)authData->username);
        return WOLFSSH_USERAUTH_INVALID_PUBLICKEY;
    }

    (void)is_ota_user;  /* used by session routing after accept */
    return WOLFSSH_USERAUTH_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* Bridge: SSH channel ↔ ring buffers                                  */
/* ------------------------------------------------------------------ */

typedef struct {
    WOLFSSH *ssh;
    ring_t  *ring;
} pump_arg_t;

/* SSH stream → ring (ssh_to_usb direction) */
static int ssh_read_cb(void *ctx, uint8_t *buf, size_t cap)
{
    WOLFSSH *ssh = (WOLFSSH *)ctx;
    int n = wolfSSH_stream_read(ssh, buf, (word32)cap);
    if (n == WS_WANT_READ) return 0;  /* no data yet, retry */
    if (n <= 0) return -1;
    return n;
}

static int ring_write_cb(void *ctx, const uint8_t *buf, size_t len)
{
    return ring_send((ring_t *)ctx, buf, len);
}

/* ring → SSH stream (usb_to_ssh direction) */
static int ring_read_cb(void *ctx, uint8_t *buf, size_t cap)
{
    return ring_recv((ring_t *)ctx, buf, cap);
}

static int ssh_write_cb(void *ctx, const uint8_t *buf, size_t len)
{
    WOLFSSH *ssh = (WOLFSSH *)ctx;
    int n = wolfSSH_stream_send(ssh, (byte *)buf, (word32)len);
    if (n <= 0) return -1;
    return n;
}

static void pump_ssh_to_usb(void *arg)
{
    pump_arg_t *a = (pump_arg_t *)arg;
    bridge_pump(ssh_read_cb,  a->ssh,
                ring_write_cb, a->ring,
                &s_pump_stop);
    /* Signal the other direction to stop */
    s_pump_stop = true;
    ring_close(a->ring);
    free(a);
    vTaskDelete(NULL);
}

static void pump_usb_to_ssh(void *arg)
{
    pump_arg_t *a = (pump_arg_t *)arg;
    bridge_pump(ring_read_cb, a->ring,
                ssh_write_cb, a->ssh,
                &s_pump_stop);
    s_pump_stop = true;
    free(a);
    vTaskDelete(NULL);
}

/* ------------------------------------------------------------------ */
/* Session teardown                                                    */
/* ------------------------------------------------------------------ */

static void teardown_active_session(void)
{
    /* Caller must hold s_session_mutex */
    if (s_active_ssh == NULL) return;

    s_pump_stop = true;

    wolfSSH_shutdown(s_active_ssh);
    if (s_active_fd >= 0) {
        close(s_active_fd);
        s_active_fd = -1;
    }
    wolfSSH_free(s_active_ssh);
    s_active_ssh = NULL;

    /* Give pump tasks a moment to see the stop flag and exit */
    vTaskDelay(pdMS_TO_TICKS(100));
}

/* ------------------------------------------------------------------ */
/* SSH server accept loop                                              */
/* ------------------------------------------------------------------ */

static void ssh_server_task(void *arg)
{
    (void)arg;

    /* TCP listen socket */
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        ESP_LOGE(TAG, "socket() failed");
        vTaskDelete(NULL);
        return;
    }

    int yes = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port        = htons(SSH_PORT),
    };
    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        listen(listen_fd, 1) < 0) {
        ESP_LOGE(TAG, "bind/listen failed");
        close(listen_fd);
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "Listening on TCP port %d", SSH_PORT);

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t          client_sz = sizeof(client_addr);

        int client_fd = accept(listen_fd,
                               (struct sockaddr *)&client_addr, &client_sz);
        if (client_fd < 0) {
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }

        ESP_LOGI(TAG, "New TCP connection");

        xSemaphoreTake(s_session_mutex, portMAX_DELAY);

        /* Single-session takeover */
        teardown_active_session();

        WOLFSSH *ssh = wolfSSH_new(s_ctx);
        if (!ssh) {
            ESP_LOGE(TAG, "wolfSSH_new failed");
            close(client_fd);
            xSemaphoreGive(s_session_mutex);
            continue;
        }

        wolfSSH_set_fd(ssh, client_fd);
        s_active_ssh = ssh;
        s_active_fd  = client_fd;
        s_pump_stop   = false;

        xSemaphoreGive(s_session_mutex);

        /* 30 s timeout for handshake + auth — prevents a slow/malicious
         * client from holding the session slot indefinitely. */
        struct timeval tv = { .tv_sec = 30, .tv_usec = 0 };
        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        /* SSH handshake + auth (blocking, bounded by SO_RCVTIMEO) */
        int ret = wolfSSH_accept(ssh);
        if (ret != WS_SUCCESS) {
            ESP_LOGW(TAG, "wolfSSH_accept failed: %d (err %d)",
                     ret, wolfSSH_get_error(ssh));
            xSemaphoreTake(s_session_mutex, portMAX_DELAY);
            teardown_active_session();
            xSemaphoreGive(s_session_mutex);
            continue;
        }

        ESP_LOGI(TAG, "SSH session established");

        /* Remove the handshake timeout — normal I/O has no deadline. */
        struct timeval tv_off = { 0 };
        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv_off, sizeof(tv_off));

        /* Check if this is an OTA session (username == "ota") */
        char username_buf[16] = {0};
        const char *uname = wolfSSH_GetUsername(ssh);
        if (uname) strncpy(username_buf, uname, sizeof(username_buf) - 1);

        if (strcmp(username_buf, "ota") == 0) {
            ESP_LOGI(TAG, "OTA session — routing to ota_session_handler");
            xSemaphoreGive(s_session_mutex);
            /* ota_session_handler owns the SSH session and may reboot */
            ota_session_handler(ssh);
            /* If we get here, OTA failed — clean up */
            xSemaphoreTake(s_session_mutex, portMAX_DELAY);
            teardown_active_session();
            xSemaphoreGive(s_session_mutex);
            continue;
        }

        /* Launch bridge pump tasks */
        pump_arg_t *a2b = malloc(sizeof(*a2b));
        pump_arg_t *b2a = malloc(sizeof(*b2a));
        if (!a2b || !b2a) {
            free(a2b); free(b2a);
            ESP_LOGE(TAG, "OOM for pump args");
            xSemaphoreTake(s_session_mutex, portMAX_DELAY);
            teardown_active_session();
            xSemaphoreGive(s_session_mutex);
            continue;
        }

        a2b->ssh  = ssh; a2b->ring = s_ssh_to_usb;
        b2a->ring = s_usb_to_ssh; b2a->ssh = ssh;

        xTaskCreate(pump_ssh_to_usb, "pump_a2b", 8192, a2b, 6, NULL);
        xTaskCreate(pump_usb_to_ssh, "pump_b2a", 8192, b2a, 6, NULL);

        /* Block until the session ends (pump tasks set s_pump_stop) */
        while (!s_pump_stop) {
            vTaskDelay(pdMS_TO_TICKS(200));
        }

        ESP_LOGI(TAG, "Session ended, cleaning up");
        xSemaphoreTake(s_session_mutex, portMAX_DELAY);
        teardown_active_session();
        xSemaphoreGive(s_session_mutex);
    }
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

esp_err_t ssh_server_start(ring_t *usb_to_ssh, ring_t *ssh_to_usb)
{
    s_usb_to_ssh = usb_to_ssh;
    s_ssh_to_usb = ssh_to_usb;

    /* Precompute authorized key hash */
    if (!pubkey_compute_hash(AUTHORIZED_PUBKEY, s_authkey_hash)) {
        ESP_LOGE(TAG, "Failed to parse AUTHORIZED_PUBKEY from config.h");
        return ESP_ERR_INVALID_ARG;
    }
    s_authkey_hash_ready = true;

    /* Precompute OTA authorized key hash (optional — OTA disabled if not configured) */
#ifdef OTA_AUTHORIZED_PUBKEY
    if (pubkey_compute_hash(OTA_AUTHORIZED_PUBKEY, s_ota_authkey_hash)) {
        s_ota_authkey_hash_ready = true;
        ESP_LOGI(TAG, "OTA pubkey auth configured");
    } else {
        ESP_LOGW(TAG, "OTA_AUTHORIZED_PUBKEY in config.h is invalid — OTA disabled");
    }
#else
    ESP_LOGW(TAG, "OTA_AUTHORIZED_PUBKEY not defined in config.h — OTA disabled");
#endif

    /* wolfSSH init */
    if (wolfSSH_Init() != WS_SUCCESS) {
        ESP_LOGE(TAG, "wolfSSH_Init failed");
        return ESP_FAIL;
    }

    s_ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (!s_ctx) {
        ESP_LOGE(TAG, "wolfSSH_CTX_new failed");
        return ESP_FAIL;
    }

    wolfSSH_SetUserAuth(s_ctx, user_auth_callback);

    esp_err_t err = host_key_load_or_generate(s_ctx);
    if (err != ESP_OK) return err;

    s_session_mutex = xSemaphoreCreateMutex();

    /* 16 KB stack — wolfSSH + wolfCrypt need at least 8–12 KB */
    BaseType_t rc = xTaskCreate(ssh_server_task, "ssh_server",
                                16384, NULL, 5, NULL);
    if (rc != pdPASS) {
        ESP_LOGE(TAG, "Failed to create ssh_server task");
        return ESP_ERR_NO_MEM;
    }

    return ESP_OK;
}
