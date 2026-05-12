/*
 * ssh_server.c -- wolfSSH server: accept loop, auth, bidirectional bridge
 *
 * Architecture:
 *   ssh_server_task (one FreeRTOS task, portMAX_DELAY on accept)
 *     -> per-session: two bridge tasks (ssh_to_usb, usb_to_ssh)
 *
 * Single-session takeover: when a second client connects while one is active,
 * the old session is torn down and the new one takes over.
 */

#include "ssh_server.h"
#include "scrollback.h"
#include "host_key.h"
#include "pubkey_auth.h"
#include "bridge.h"
#include "term_resize.h"
#include "ota_session.h"
#include "config.h"   /* SSH_PORT, AUTHORIZED_PUBKEYS, OTA_AUTHORIZED_PUBKEY */

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
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
static scrollback_t *s_scrollback  = NULL;

/* Active session (protected by s_session_mutex) */
static SemaphoreHandle_t s_session_mutex;
static WOLFSSH      *s_active_ssh  = NULL;
static int           s_active_fd   = -1;
static volatile bool s_pump_stop   = false;
static bool          s_pumps_running = false;  /* true only while both pump tasks are live */

/*
 * Counting semaphore for pump task completion synchronisation.
 * Initial count = 0; each pump task gives once just before vTaskDelete.
 * teardown_active_session() takes twice (once per pump direction) to confirm
 * both tasks have exited before wolfSSH_free() is called.
 * Without this, an old pump task could continue calling wolfSSH_stream_read
 * on a freed pointer (use-after-free) if it did not see s_pump_stop=true
 * within the old 100 ms heuristic delay.
 */
static SemaphoreHandle_t s_pump_done_sem = NULL;

/* Maximum number of TTY pubkeys to load from AUTHORIZED_PUBKEYS.
 * Bump in config.h if you need more than 8 keys. */
#ifndef MAX_TTY_KEYS
#define MAX_TTY_KEYS 8
#endif

/* SSH handshake + auth timeout (seconds). The first wolfSSH_accept() call
 * blocks until this many seconds elapse with no progress; protects against
 * slow/malicious clients holding the session slot. */
#ifndef SSH_HANDSHAKE_TIMEOUT_SEC
#define SSH_HANDSHAKE_TIMEOUT_SEC 30
#endif

/* TCP keepalive: detect silently-dropped connections.
 *   IDLE  = seconds of inactivity before the first probe
 *   INTVL = seconds between subsequent probes
 *   COUNT = number of unanswered probes before the connection is dropped
 * Defaults (60/10/3) detect a dead peer in ~90 s. Tune up for cellular
 * links (e.g. 600/60/3), down for fragile LANs. */
#ifndef TCP_KEEPALIVE_IDLE_SEC
#define TCP_KEEPALIVE_IDLE_SEC   60
#endif
#ifndef TCP_KEEPALIVE_INTVL_SEC
#define TCP_KEEPALIVE_INTVL_SEC  10
#endif
#ifndef TCP_KEEPALIVE_COUNT
#define TCP_KEEPALIVE_COUNT      3
#endif

/* Number of lines of scrollback to replay when a new SSH client connects.
 * Lower this if you find the connect-time scrollback too noisy. */
#ifndef SCROLLBACK_REPLAY_LINES
#define SCROLLBACK_REPLAY_LINES  SCROLLBACK_DEFAULT_LINES   /* 1000 */
#endif

/* Precomputed SHA-256 hashes for all TTY authorized keys (AUTHORIZED_PUBKEYS). */
static uint8_t s_authkey_hashes[MAX_TTY_KEYS][PUBKEY_HASH_SIZE];
static int     s_authkey_count = 0;

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

    if (s_authkey_count == 0)
        return WOLFSSH_USERAUTH_FAILURE;

    pubkey_user_class_t uclass = pubkey_classify_user(
        (const char *)authData->username, authData->usernameSz);

    if (uclass == PUBKEY_USER_REJECTED) {
        ESP_LOGW(TAG, "Auth rejected: unknown username '%.*s'",
                 (int)authData->usernameSz, (const char *)authData->username);
        return WOLFSSH_USERAUTH_FAILURE;
    }

    if (uclass == PUBKEY_USER_OTA) {
        if (!s_ota_authkey_hash_ready) {
            ESP_LOGW(TAG, "OTA auth attempted but OTA key not configured");
            return WOLFSSH_USERAUTH_FAILURE;
        }
        if (pubkey_auth_check(authData->sf.publicKey.publicKey,
                              authData->sf.publicKey.publicKeySz,
                              s_ota_authkey_hash) == PUBKEY_AUTH_OK)
            return WOLFSSH_USERAUTH_SUCCESS;
        ESP_LOGW(TAG, "Auth rejected: unknown public key (user=ota)");
        return WOLFSSH_USERAUTH_INVALID_PUBLICKEY;
    }

    /* PUBKEY_USER_TTY: accept if any configured key matches */
    for (int i = 0; i < s_authkey_count; i++) {
        if (pubkey_auth_check(authData->sf.publicKey.publicKey,
                              authData->sf.publicKey.publicKeySz,
                              s_authkey_hashes[i]) == PUBKEY_AUTH_OK)
            return WOLFSSH_USERAUTH_SUCCESS;
    }
    ESP_LOGW(TAG, "Auth rejected: unknown public key (user=%.*s)",
             (int)authData->usernameSz, (const char *)authData->username);
    return WOLFSSH_USERAUTH_INVALID_PUBLICKEY;
}

/* ------------------------------------------------------------------ */
/* Terminal resize callback                                            */
/* ------------------------------------------------------------------ */

static int term_resize_cb(WOLFSSH *ssh, word32 cols, word32 rows,
                          word32 widthPx, word32 heightPx, void *ctx)
{
    (void)ssh; (void)widthPx; (void)heightPx;
    if (!ctx || cols == 0 || rows == 0) return WS_SUCCESS;
    ring_t *ring = (ring_t *)ctx;
    /* Inject xterm "set window size" CSI into the USB-bound stream.
     * \033[8;rows;colst -- received by the Linux host's terminal layer. */
    char seq[32];
    int n = term_resize_format(cols, rows, seq, sizeof seq);
    if (n > 0)
        ring_send(ring, (const uint8_t *)seq, (size_t)n);
    return WS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* Bridge: SSH channel <-> ring buffers                                  */
/* ------------------------------------------------------------------ */

typedef struct {
    WOLFSSH *ssh;
    ring_t  *ring;
} pump_arg_t;

/* SSH stream -> ring (ssh_to_usb direction) */
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

/* ring -> SSH stream (usb_to_ssh direction) */
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
    free(a);
    /* Signal teardown that this pump direction has exited.
     * teardown_active_session() waits on s_pump_done_sem twice before
     * calling wolfSSH_free(), preventing use-after-free. */
    if (s_pump_done_sem) xSemaphoreGive(s_pump_done_sem);
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
    /* Signal teardown that this pump direction has exited. */
    if (s_pump_done_sem) xSemaphoreGive(s_pump_done_sem);
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
    /* Unblock pump_usb_to_ssh which may be blocked on ring_recv(s_usb_to_ssh). */
    ring_close(s_usb_to_ssh);

    /* Close the socket first: this makes wolfSSH_stream_read/send in the pump
     * tasks return an error, causing them to exit.  We must NOT call any
     * wolfSSH_* functions here while the pumps may still be inside wolfSSH --
     * wolfSSL is not thread-safe and concurrent access corrupts the heap. */
    if (s_active_fd >= 0) {
        close(s_active_fd);
        s_active_fd = -1;
    }

    /* Wait for both pump tasks to signal completion before touching wolfSSH.
     * Each pump task gives s_pump_done_sem once just before vTaskDelete;
     * we take twice (one per direction). Timeout of 5 s is a safety net.
     * Only wait when pump tasks were actually launched (not for OTA sessions
     * or failed handshakes where pump tasks were never started). */
    if (s_pumps_running && s_pump_done_sem) {
        TickType_t timeout = pdMS_TO_TICKS(5000);
        if (xSemaphoreTake(s_pump_done_sem, timeout) != pdTRUE)
            ESP_LOGW(TAG, "teardown: pump_ssh_to_usb did not exit within 5 s");
        if (xSemaphoreTake(s_pump_done_sem, timeout) != pdTRUE)
            ESP_LOGW(TAG, "teardown: pump_usb_to_ssh did not exit within 5 s");
        s_pumps_running = false;
    }

    /* Pumps are gone -- now safe to call wolfSSH_free.  We skip wolfSSH_shutdown
     * because the socket is already closed: there is no way to send the SSH
     * disconnect packet to the peer.  The peer will see the TCP RST/FIN. */
    wolfSSH_free(s_active_ssh);
    s_active_ssh = NULL;
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

        /* Bounded timeout for handshake + auth -- prevents a slow/malicious
         * client from holding the session slot indefinitely. */
        struct timeval tv = { .tv_sec = SSH_HANDSHAKE_TIMEOUT_SEC, .tv_usec = 0 };
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

        /* Remove the handshake timeout -- normal I/O has no deadline. */
        struct timeval tv_off = { 0 };
        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv_off, sizeof(tv_off));

        /* TCP keepalive: detect silently-dropped connections.
         * After 60 s idle, send a probe every 10 s; give up after 3 misses. */
        int ka_on    = 1;
        int ka_idle  = TCP_KEEPALIVE_IDLE_SEC;
        int ka_intvl = TCP_KEEPALIVE_INTVL_SEC;
        int ka_cnt   = TCP_KEEPALIVE_COUNT;
        setsockopt(client_fd, SOL_SOCKET,  SO_KEEPALIVE,  &ka_on,    sizeof(ka_on));
        setsockopt(client_fd, IPPROTO_TCP, TCP_KEEPIDLE,  &ka_idle,  sizeof(ka_idle));
        setsockopt(client_fd, IPPROTO_TCP, TCP_KEEPINTVL, &ka_intvl, sizeof(ka_intvl));
        setsockopt(client_fd, IPPROTO_TCP, TCP_KEEPCNT,   &ka_cnt,   sizeof(ka_cnt));

        /* Check if this is an OTA session (username == "ota") */
        const char *uname = wolfSSH_GetUsername(ssh);
        if (pubkey_classify_user(uname, uname ? strlen(uname) : 0) == PUBKEY_USER_OTA) {
            ESP_LOGI(TAG, "OTA session -- routing to ota_session_handler");
            xSemaphoreGive(s_session_mutex);
            /* ota_session_handler owns the SSH session and may reboot */
            ota_session_handler(ssh);
            /* If we get here, OTA failed -- clean up */
            xSemaphoreTake(s_session_mutex, portMAX_DELAY);
            teardown_active_session();
            xSemaphoreGive(s_session_mutex);
            continue;
        }

        /* Register terminal resize callback -- forwards window-change events
         * from the SSH client as CSI sequences into the USB-bound ring. */
        wolfSSH_SetTerminalResizeCb(ssh, term_resize_cb);
        wolfSSH_SetTerminalResizeCtx(ssh, s_ssh_to_usb);

        /* Replay scrollback before going live -------------------------
         * Send the last SCROLLBACK_REPLAY_LINES lines of USB device
         * output so the user sees e.g. kernel panics or boot logs that
         * arrived while no SSH client was connected. */
        if (s_scrollback) {
            size_t dump_len = 0;
            uint8_t *dump = scrollback_get_lines(s_scrollback,
                                                 SCROLLBACK_REPLAY_LINES,
                                                 &dump_len);
            if (dump && dump_len > 0) {
                /* Count lines + format header via the scrollback library so
                 * the formatting is unit-testable on the native host. */
                int  line_count = scrollback_count_newlines(dump, dump_len);
                char hdr[64];
                int  hdr_len = scrollback_format_header(line_count,
                                                        hdr, sizeof hdr);
                if (hdr_len > 0)
                    wolfSSH_stream_send(ssh, (byte *)hdr, (word32)hdr_len);

                const uint8_t *p = dump;
                size_t rem = dump_len;
                while (rem > 0) {
                    int n = wolfSSH_stream_send(ssh, (byte *)p, (word32)rem);
                    if (n <= 0) break;
                    p   += (size_t)n;
                    rem -= (size_t)n;
                }

                const char *footer = SCROLLBACK_FOOTER;
                wolfSSH_stream_send(ssh, (byte *)footer,
                                    (word32)strlen(footer));
                free(dump);
            }
        }

        /* Re-open rings in case they were closed by the previous session's
         * pump exit.  Must happen before pump tasks start reading/writing. */
        ring_reopen(s_ssh_to_usb);
        ring_reopen(s_usb_to_ssh);

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

        s_pumps_running = true;
        xTaskCreate(pump_ssh_to_usb, "pump_a2b", 8192, a2b, 6, NULL);
        xTaskCreate(pump_usb_to_ssh, "pump_b2a", 8192, b2a, 6, NULL);

        /* Block until the session ends (pump tasks set s_pump_stop), but
         * also poll the listen socket so an incoming connection preempts the
         * current session. Without this, a new client would queue in the
         * kernel backlog until the current session naturally ends. */
        while (!s_pump_stop) {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(listen_fd, &rfds);
            struct timeval ptv = { .tv_sec = 0, .tv_usec = 200000 };
            int sel = select(listen_fd + 1, &rfds, NULL, NULL, &ptv);
            if (sel > 0 && FD_ISSET(listen_fd, &rfds)) {
                ESP_LOGI(TAG, "New connection pending -- preempting session");
                s_pump_stop = true;
                break;
            }
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

esp_err_t ssh_server_start(ring_t *usb_to_ssh, ring_t *ssh_to_usb,
                           scrollback_t *scrollback)
{
    s_usb_to_ssh = usb_to_ssh;
    s_ssh_to_usb = ssh_to_usb;
    s_scrollback = scrollback;

    /* Precompute hashes for all TTY authorized keys */
    {
        static const char *const keys[] = { AUTHORIZED_PUBKEYS };
        int n = (int)(sizeof(keys) / sizeof(keys[0]));
        if (n > MAX_TTY_KEYS) n = MAX_TTY_KEYS;
        for (int i = 0; i < n; i++) {
            if (pubkey_compute_hash(keys[i], s_authkey_hashes[s_authkey_count]))
                s_authkey_count++;
            else
                ESP_LOGW(TAG, "Failed to parse TTY key %d from config.h", i);
        }
    }
    if (s_authkey_count == 0) {
        ESP_LOGE(TAG, "No valid keys in AUTHORIZED_PUBKEYS");
        return ESP_ERR_INVALID_ARG;
    }
    ESP_LOGI(TAG, "%d TTY key(s) loaded", s_authkey_count);

    /* Precompute OTA authorized key hash (optional -- OTA disabled if not configured) */
#ifdef OTA_AUTHORIZED_PUBKEY
    if (pubkey_compute_hash(OTA_AUTHORIZED_PUBKEY, s_ota_authkey_hash)) {
        s_ota_authkey_hash_ready = true;
        ESP_LOGI(TAG, "OTA pubkey auth configured");
    } else {
        ESP_LOGW(TAG, "OTA_AUTHORIZED_PUBKEY in config.h is invalid -- OTA disabled");
    }
#else
    ESP_LOGW(TAG, "OTA_AUTHORIZED_PUBKEY not defined in config.h -- OTA disabled");
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

    /* Pin cipher negotiation to AES-256-GCM only.
     * wolfSSH's default cannedEncAlgoNames includes aes192-gcm@openssh.com
     * alongside aes256-gcm and aes128-gcm; NO_AES_192 (in user_settings.h)
     * prevents the 192-bit key path from being compiled, but we also
     * advertise only what we want: one cipher, one key size. */
    wolfSSH_CTX_SetAlgoListCipher(s_ctx, "aes256-gcm@openssh.com");

    esp_err_t err = host_key_load_or_generate(s_ctx);
    if (err != ESP_OK) return err;

    s_session_mutex = xSemaphoreCreateMutex();

    /* Counting semaphore for pump-task exit synchronisation.
     * Max count = 2 (one per pump direction); initial count = 0. */
    s_pump_done_sem = xSemaphoreCreateCounting(2, 0);
    if (!s_pump_done_sem) {
        ESP_LOGE(TAG, "Failed to create s_pump_done_sem");
        return ESP_ERR_NO_MEM;
    }

    /* 16 KB stack -- wolfSSH + wolfCrypt need at least 8-12 KB */
    BaseType_t rc = xTaskCreate(ssh_server_task, "ssh_server",
                                16384, NULL, 5, NULL);
    if (rc != pdPASS) {
        ESP_LOGE(TAG, "Failed to create ssh_server task");
        return ESP_ERR_NO_MEM;
    }

    return ESP_OK;
}
