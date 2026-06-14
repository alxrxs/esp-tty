/* Native test stub: sha256.h backed by OpenSSL EVP (OpenSSL 3 compatible) */
#pragma once
#include <openssl/evp.h>
#include <stdlib.h>
#include "wolfssl/wolfcrypt/settings.h"

#define WC_SHA256_DIGEST_SIZE 32

typedef struct { EVP_MD_CTX *ctx; } Sha256;

/*
 * Fault-injection seam (native tests only).
 *
 * Real wc_Sha256* calls can fail on hardware (HW-accel busy/timeout, OOM in
 * the SW path).  The OpenSSL-backed stub never fails on its own, so to test
 * the failure-handling paths in pubkey_auth.c we let a test force a single
 * call to return an error.
 *
 *   wc_sha256_fail_at_init   -- next wc_InitSha256   returns -1 (then clears)
 *   wc_sha256_fail_at_update -- next wc_Sha256Update returns -1 (then clears)
 *   wc_sha256_fail_at_final  -- next wc_Sha256Final  returns -1 (then clears)
 *
 * Each flag is one-shot: it is consumed (reset to 0) by the call it trips, so
 * a test sets it immediately before the operation under test.  Production code
 * never references these symbols.
 *
 * The flags need EXTERNAL linkage so the test TU and the TU under test
 * (pubkey_auth.c) share the same flag -- they are distinct translation units
 * linked into one program.  We use a single __attribute__((weak)) definition
 * in this header: every TU that includes the stub emits a weak definition and
 * the linker collapses them to one shared object, with no separate stub .c
 * file required.  Weak symbols are harmless in test programs that never touch
 * the flags.
 */
__attribute__((weak)) int wc_sha256_fail_at_init   = 0;
__attribute__((weak)) int wc_sha256_fail_at_update = 0;
__attribute__((weak)) int wc_sha256_fail_at_final  = 0;

static inline int wc_InitSha256(Sha256 *s) {
    if (wc_sha256_fail_at_init) {
        wc_sha256_fail_at_init = 0;
        s->ctx = NULL;
        return -1;
    }
    s->ctx = EVP_MD_CTX_new();
    if (!s->ctx) return -1;
    EVP_DigestInit_ex(s->ctx, EVP_sha256(), NULL);
    return 0;
}
static inline int wc_Sha256Update(Sha256 *s, const byte *d, word32 n) {
    if (wc_sha256_fail_at_update) {
        wc_sha256_fail_at_update = 0;
        return -1;
    }
    EVP_DigestUpdate(s->ctx, d, n);
    return 0;
}
static inline int wc_Sha256Final(Sha256 *s, byte *out) {
    if (wc_sha256_fail_at_final) {
        wc_sha256_fail_at_final = 0;
        return -1;
    }
    unsigned int len = WC_SHA256_DIGEST_SIZE;
    EVP_DigestFinal_ex(s->ctx, out, &len);
    EVP_MD_CTX_free(s->ctx);
    s->ctx = NULL;
    return 0;
}
/* Mirror wc_Sha256Free (void return in real wolfSSL).  Idempotent: safe to
 * call after wc_Sha256Final (which already frees+NULLs ctx) or on an error
 * path before Final ran. */
static inline void wc_Sha256Free(Sha256 *s) {
    if (s && s->ctx) {
        EVP_MD_CTX_free(s->ctx);
        s->ctx = NULL;
    }
}
