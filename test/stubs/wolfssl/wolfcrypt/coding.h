/* Native test stub: coding.h -- Base64_Decode backed by OpenSSL */
#pragma once
#include <openssl/evp.h>
#include <string.h>
#include <stdlib.h>
#include "wolfssl/wolfcrypt/settings.h"

/* wolfCrypt return codes used by pubkey_auth.c */
#define BAD_FUNC_ARG  (-173)
#define BUFFER_E      (-132)

static inline int Base64_Decode(const byte *in, word32 inLen,
                                 byte *out,       word32 *outLen)
{
    if (!in || !out || !outLen) return BAD_FUNC_ARG;

    /* Decode into a temporary heap buffer so we can check the size before
     * writing to the caller-supplied output (which may be smaller).
     * wolfCrypt's real Base64_Decode returns BUFFER_E if *outLen is too small.
     */
    word32 max_out = *outLen;

    /* Upper bound on decoded length: 3/4 of base64 input, rounded up */
    word32 tmp_cap = ((inLen + 3) / 4) * 3 + 4;
    byte *tmp = (byte *)malloc(tmp_cap);
    if (!tmp) return BAD_FUNC_ARG;

    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
    if (!ctx) { free(tmp); return BAD_FUNC_ARG; }

    int written = 0, final = 0;
    EVP_DecodeInit(ctx);
    /* EVP_DecodeUpdate wants a newline-terminated block or raw base64 */
    if (EVP_DecodeUpdate(ctx, tmp, &written, in, (int)inLen) < 0) {
        EVP_ENCODE_CTX_free(ctx);
        free(tmp);
        return BUFFER_E;
    }
    if (EVP_DecodeFinal(ctx, tmp + written, &final) < 0) {
        EVP_ENCODE_CTX_free(ctx);
        free(tmp);
        return BUFFER_E;
    }
    EVP_ENCODE_CTX_free(ctx);

    word32 decoded_len = (word32)(written + final);
    if (decoded_len > max_out) {
        /* Decoded data exceeds caller's buffer -- mimic wolfCrypt BUFFER_E */
        free(tmp);
        return BUFFER_E;
    }

    memcpy(out, tmp, decoded_len);
    free(tmp);
    *outLen = decoded_len;
    return 0;
}
