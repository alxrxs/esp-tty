/*
 * roundtrip_verify.c -- standalone host-side OTA verifier for the signer roundtrip test
 *
 * Usage:
 *   roundtrip_verify <signed.bin> <pub.pem> <aes.key> [--tamper-byte <offset>]
 *
 * Reads the signed OTA image, public key PEM, and raw 32-byte AES key from
 * the given files, then calls ota_verify_begin/feed/end.
 *
 * Exit codes:
 *   0 -- OTA_VERIFY_OK
 *   1 -- verification failed (prints error)
 *   2 -- usage or I/O error
 *
 * Compiled with -DOTA_VERIFY_NATIVE_TEST so the mbedtls/OpenSSL stubs are used.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ota_verify.h"

static uint8_t *read_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "[roundtrip_verify] Cannot open file: %s\n", path);
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); return NULL; }
    /* sz == 0 is valid (empty file) */
    uint8_t *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t n = (sz > 0) ? fread(buf, 1, (size_t)sz, f) : 0;
    fclose(f);
    if (n != (size_t)sz) { free(buf); return NULL; }
    buf[n] = '\0';   /* NUL-terminate for PEM strings */
    *out_len = n;
    return buf;
}

int main(int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <signed.bin> <pub.pem> <aes.key> [--tamper-byte <offset>]\n",
                argv[0]);
        return 2;
    }

    const char *bin_path = argv[1];
    const char *pem_path = argv[2];
    const char *aes_path = argv[3];

    long tamper_offset = -1;
    for (int i = 4; i < argc - 1; i++) {
        if (strcmp(argv[i], "--tamper-byte") == 0) {
            tamper_offset = atol(argv[i + 1]);
        }
    }

    /* Read signed image */
    size_t img_len = 0;
    uint8_t *img = read_file(bin_path, &img_len);
    if (!img) {
        fprintf(stderr, "[roundtrip_verify] Failed to read: %s\n", bin_path);
        return 2;
    }

    /* Read public key PEM (NUL-terminated string) */
    size_t pem_len = 0;
    uint8_t *pem = read_file(pem_path, &pem_len);
    if (!pem) {
        fprintf(stderr, "[roundtrip_verify] Failed to read: %s\n", pem_path);
        free(img);
        return 2;
    }
    /* Include NUL terminator in the length (mbedtls_pk_parse_public_key requires it) */
    size_t pem_len_with_nul = pem_len + 1;

    /* Read raw AES key */
    size_t aes_len = 0;
    uint8_t *aes_raw = read_file(aes_path, &aes_len);
    if (!aes_raw) {
        fprintf(stderr, "[roundtrip_verify] Failed to read: %s\n", aes_path);
        free(img); free(pem);
        return 2;
    }
    if (aes_len != 32) {
        fprintf(stderr, "[roundtrip_verify] AES key must be 32 bytes, got %zu\n", aes_len);
        free(img); free(pem); free(aes_raw);
        return 2;
    }

    /* Optionally tamper one byte */
    if (tamper_offset >= 0 && (size_t)tamper_offset < img_len) {
        fprintf(stderr, "[roundtrip_verify] Tampering byte at offset %ld\n", tamper_offset);
        img[tamper_offset] ^= 0x01;
    }

    /* Run the verifier */
    ota_verify_ctx_t *ctx = ota_verify_begin(pem, pem_len_with_nul, aes_raw);
    if (!ctx) {
        fprintf(stderr, "[roundtrip_verify] ota_verify_begin returned NULL\n");
        free(img); free(pem); free(aes_raw);
        return 1;
    }

    ota_verify_err_t e = ota_verify_feed(ctx, img, img_len, img_len);
    if (e != OTA_VERIFY_OK) {
        fprintf(stderr, "[roundtrip_verify] ota_verify_feed failed: %s (%d)\n",
                ota_verify_strerror(e), (int)e);
        ota_verify_abort(ctx);
        free(img); free(pem); free(aes_raw);
        return 1;
    }

    e = ota_verify_end(ctx);
    if (e != OTA_VERIFY_OK) {
        fprintf(stderr, "[roundtrip_verify] ota_verify_end failed: %s (%d)\n",
                ota_verify_strerror(e), (int)e);
        free(img); free(pem); free(aes_raw);
        return 1;
    }

    printf("[roundtrip_verify] OTA_VERIFY_OK -- image verified successfully\n");
    free(img); free(pem); free(aes_raw);
    return 0;
}
