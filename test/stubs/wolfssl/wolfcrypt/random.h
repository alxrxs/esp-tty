/* Native test stub: random.h -- WC_RNG backed by /dev/urandom via OpenSSL */
#pragma once
#include <openssl/rand.h>
#include <string.h>
#include "wolfssl/wolfcrypt/settings.h"

typedef struct WC_RNG {
    int initialized;
} WC_RNG;

static inline int wc_InitRng(WC_RNG *rng) {
    if (!rng) return -1;
    rng->initialized = 1;
    return 0;
}

static inline int wc_FreeRng(WC_RNG *rng) {
    if (rng) rng->initialized = 0;
    return 0;
}

static inline int wc_RNG_GenerateBlock(WC_RNG *rng, byte *buf, word32 sz) {
    (void)rng;
    return RAND_bytes(buf, (int)sz) == 1 ? 0 : -1;
}
