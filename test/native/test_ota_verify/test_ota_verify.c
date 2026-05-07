/*
 * test_ota_verify.c — unit tests for ota_verify.c (native, no hardware)
 *
 * Compiled with OTA_VERIFY_NATIVE_TEST which replaces ESP-IDF OTA/flash APIs
 * with no-ops and uses test/stubs/mbedtls/ (OpenSSL-backed) for crypto.
 *
 * Golden test vectors generated with scripts/sign_firmware.py logic in Python.
 */

#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "unity.h"
#include "ota_verify.h"

void setUp(void)    {}
void tearDown(void) {}

/* ── Golden test vectors ─────────────────────────────────────────────────── */
/*
 * Generated with:
 *   python3 -c "
 *     from cryptography.hazmat.primitives.asymmetric import ec, utils as au
 *     from cryptography.hazmat.primitives import hashes, serialization
 *     from cryptography.hazmat.primitives.ciphers.aead import AESGCM
 *     from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
 *     import os, struct, hashlib
 *     MAGIC = b'ESPOTA1\x00'; VERSION = 1
 *     privkey = ec.generate_private_key(ec.SECP256R1())
 *     pub_pem = privkey.public_key().public_bytes(serialization.Encoding.PEM,
 *               serialization.PublicFormat.SubjectPublicKeyInfo)
 *     aes_key = os.urandom(32); iv = os.urandom(12)
 *     plaintext = b'Hello OTA test firmware!' * 4
 *     ct_and_tag = AESGCM(aes_key).encrypt(iv, plaintext, None)
 *     ciphertext, tag = ct_and_tag[:-16], ct_and_tag[-16:]
 *     header = MAGIC + struct.pack('<II', VERSION, len(plaintext)) + iv + tag
 *     signed_region = header + ciphertext
 *     digest = hashlib.sha256(signed_region).digest()
 *     sig_der = privkey.sign(digest, ec.ECDSA(au.Prehashed(hashes.SHA256())))
 *     r, s = decode_dss_signature(sig_der)
 *     sig = r.to_bytes(32,'big') + s.to_bytes(32,'big')
 *     ota_image = signed_region + sig
 *     ..."
 */

static const uint8_t TEST_AES_KEY[] = {
    0x1a, 0x4b, 0x11, 0x0d, 0x19, 0x78, 0xb4, 0x61, 0x3d, 0x42, 0xef, 0x04,
    0x16, 0x9a, 0x26, 0x03, 0x6f, 0xb0, 0x74, 0xec, 0x68, 0x5e, 0x88, 0x2d,
    0x89, 0x70, 0x38, 0x31, 0x51, 0x5a, 0x3a, 0xf1
};

static const uint8_t TEST_PUB_PEM[] = {
    0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x50,
    0x55, 0x42, 0x4c, 0x49, 0x43, 0x20, 0x4b, 0x45, 0x59, 0x2d, 0x2d, 0x2d,
    0x2d, 0x2d, 0x0a, 0x4d, 0x46, 0x6b, 0x77, 0x45, 0x77, 0x59, 0x48, 0x4b,
    0x6f, 0x5a, 0x49, 0x7a, 0x6a, 0x30, 0x43, 0x41, 0x51, 0x59, 0x49, 0x4b,
    0x6f, 0x5a, 0x49, 0x7a, 0x6a, 0x30, 0x44, 0x41, 0x51, 0x63, 0x44, 0x51,
    0x67, 0x41, 0x45, 0x6c, 0x30, 0x67, 0x76, 0x38, 0x42, 0x55, 0x6d, 0x35,
    0x62, 0x55, 0x6a, 0x4b, 0x41, 0x44, 0x67, 0x7a, 0x68, 0x2b, 0x57, 0x33,
    0x6f, 0x74, 0x55, 0x76, 0x58, 0x50, 0x4b, 0x0a, 0x76, 0x31, 0x50, 0x4a,
    0x55, 0x43, 0x73, 0x4c, 0x45, 0x56, 0x53, 0x42, 0x71, 0x59, 0x6a, 0x31,
    0x63, 0x69, 0x37, 0x36, 0x6d, 0x2f, 0x73, 0x64, 0x6e, 0x79, 0x75, 0x58,
    0x43, 0x33, 0x44, 0x4b, 0x4f, 0x55, 0x49, 0x4a, 0x72, 0x73, 0x4d, 0x74,
    0x50, 0x68, 0x6b, 0x34, 0x56, 0x30, 0x5a, 0x55, 0x34, 0x39, 0x70, 0x57,
    0x42, 0x42, 0x4e, 0x46, 0x58, 0x67, 0x3d, 0x3d, 0x0a, 0x2d, 0x2d, 0x2d,
    0x2d, 0x2d, 0x45, 0x4e, 0x44, 0x20, 0x50, 0x55, 0x42, 0x4c, 0x49, 0x43,
    0x20, 0x4b, 0x45, 0x59, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a, 0x00
};
#define TEST_PUB_PEM_LEN sizeof(TEST_PUB_PEM)

static const uint8_t TEST_OTA_IMAGE[] = {
    0x45, 0x53, 0x50, 0x4f, 0x54, 0x41, 0x31, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x60, 0x00, 0x00, 0x00, 0xb8, 0xa6, 0x04, 0x22, 0xd4, 0xb9, 0x89, 0x2a,
    0x8e, 0xa8, 0x51, 0x73, 0x21, 0xd4, 0x6a, 0xdc, 0x74, 0xe0, 0x40, 0x23,
    0xba, 0xf1, 0x43, 0x46, 0xe2, 0xbc, 0x01, 0xa5, 0x81, 0xd1, 0xc2, 0xed,
    0xd9, 0xc0, 0x29, 0x0e, 0x78, 0x2d, 0x18, 0xa3, 0xa0, 0x76, 0xed, 0x64,
    0xae, 0x68, 0x78, 0x84, 0xcb, 0x79, 0x39, 0x77, 0x1e, 0xa7, 0xd3, 0x6e,
    0x38, 0x14, 0xe3, 0x00, 0xb6, 0x6c, 0x14, 0x8b, 0x91, 0x06, 0x7a, 0x93,
    0x84, 0x49, 0x5c, 0x47, 0x39, 0xbb, 0x6b, 0xf4, 0x8f, 0xc9, 0xbc, 0x62,
    0xcd, 0x56, 0xdd, 0xfe, 0xf1, 0x9c, 0xd7, 0x57, 0x7c, 0x4c, 0x0e, 0x32,
    0x45, 0xbf, 0x81, 0x5c, 0xca, 0xb1, 0x0a, 0xc0, 0xba, 0xd3, 0xdf, 0x2b,
    0x73, 0x5f, 0x53, 0x0d, 0xda, 0x2e, 0x2f, 0x07, 0x26, 0x88, 0x10, 0xd3,
    0x97, 0xf8, 0xe2, 0x1b, 0x0b, 0x5d, 0x53, 0xde, 0x5a, 0x6c, 0xb2, 0x96,
    0xfc, 0x66, 0x55, 0xdd, 0xdd, 0x23, 0x7e, 0x46, 0x98, 0xca, 0x78, 0xd1,
    0xbf, 0x4e, 0xc4, 0xb4, 0xdf, 0xb8, 0x7b, 0x84, 0x78, 0x34, 0xfc, 0x53,
    0x6d, 0xbf, 0x1e, 0x93, 0x20, 0x96, 0x28, 0x65, 0xe6, 0x6f, 0xa6, 0xbc,
    0x33, 0x3e, 0xbd, 0x86, 0x4d, 0xef, 0xd6, 0xe1, 0x8f, 0xe4, 0x2c, 0x8e,
    0x13, 0x10, 0x3a, 0xd6, 0x84, 0x2c, 0x87, 0x37, 0xcc, 0xd5, 0x6d, 0xe9
};
#define TEST_IMAGE_LEN  sizeof(TEST_OTA_IMAGE)

/* ── Helper: feed image in one shot ─────────────────────────────────────── */

static ota_verify_err_t run_verify(const uint8_t *img, size_t img_len,
                                    const uint8_t *pub, size_t pub_len,
                                    const uint8_t  aes[32])
{
    ota_verify_ctx_t *ctx = ota_verify_begin(pub, pub_len, aes);
    if (!ctx) return OTA_VERIFY_ERR_OOM;
    ota_verify_err_t e = ota_verify_feed(ctx, img, img_len, img_len);
    if (e != OTA_VERIFY_OK) { ota_verify_abort(ctx); return e; }
    return ota_verify_end(ctx);
}

/* Helper: feed image in small chunks */
static ota_verify_err_t run_verify_chunked(const uint8_t *img, size_t img_len,
                                            size_t chunk_size,
                                            const uint8_t *pub, size_t pub_len,
                                            const uint8_t  aes[32])
{
    ota_verify_ctx_t *ctx = ota_verify_begin(pub, pub_len, aes);
    if (!ctx) return OTA_VERIFY_ERR_OOM;
    size_t off = 0;
    while (off < img_len) {
        size_t take = img_len - off;
        if (take > chunk_size) take = chunk_size;
        ota_verify_err_t e = ota_verify_feed(ctx, img + off, take, img_len);
        if (e != OTA_VERIFY_OK) { ota_verify_abort(ctx); return e; }
        off += take;
    }
    return ota_verify_end(ctx);
}

/* ── Tests ───────────────────────────────────────────────────────────────── */

void test_golden_verifies_ok(void)
{
    ota_verify_err_t e = run_verify(
        TEST_OTA_IMAGE, TEST_IMAGE_LEN,
        TEST_PUB_PEM, TEST_PUB_PEM_LEN,
        TEST_AES_KEY);
    TEST_ASSERT_EQUAL_INT(OTA_VERIFY_OK, e);
}

void test_golden_verifies_ok_chunked_1byte(void)
{
    ota_verify_err_t e = run_verify_chunked(
        TEST_OTA_IMAGE, TEST_IMAGE_LEN, 1,
        TEST_PUB_PEM, TEST_PUB_PEM_LEN,
        TEST_AES_KEY);
    TEST_ASSERT_EQUAL_INT(OTA_VERIFY_OK, e);
}

void test_golden_verifies_ok_chunked_13bytes(void)
{
    ota_verify_err_t e = run_verify_chunked(
        TEST_OTA_IMAGE, TEST_IMAGE_LEN, 13,
        TEST_PUB_PEM, TEST_PUB_PEM_LEN,
        TEST_AES_KEY);
    TEST_ASSERT_EQUAL_INT(OTA_VERIFY_OK, e);
}

void test_tamper_ciphertext_fails_sig(void)
{
    /* Flip a byte in the ciphertext region (byte 50, inside ciphertext) */
    uint8_t tampered[TEST_IMAGE_LEN];
    memcpy(tampered, TEST_OTA_IMAGE, TEST_IMAGE_LEN);
    tampered[50] ^= 0xFF;  /* offset 50 is within ciphertext (starts at 44) */

    ota_verify_err_t e = run_verify(
        tampered, TEST_IMAGE_LEN,
        TEST_PUB_PEM, TEST_PUB_PEM_LEN,
        TEST_AES_KEY);
    /* ECDSA will fail because the signed region is hashed before sig verify */
    TEST_ASSERT_EQUAL_INT(OTA_VERIFY_ERR_SIG, e);
}

void test_tamper_signature_fails(void)
{
    /* Flip a byte in the signature (last 64 bytes) */
    uint8_t tampered[TEST_IMAGE_LEN];
    memcpy(tampered, TEST_OTA_IMAGE, TEST_IMAGE_LEN);
    tampered[TEST_IMAGE_LEN - 10] ^= 0x01;

    ota_verify_err_t e = run_verify(
        tampered, TEST_IMAGE_LEN,
        TEST_PUB_PEM, TEST_PUB_PEM_LEN,
        TEST_AES_KEY);
    TEST_ASSERT_EQUAL_INT(OTA_VERIFY_ERR_SIG, e);
}

void test_wrong_magic_fails(void)
{
    uint8_t tampered[TEST_IMAGE_LEN];
    memcpy(tampered, TEST_OTA_IMAGE, TEST_IMAGE_LEN);
    tampered[0] = 'X';  /* Break the magic */

    ota_verify_err_t e = run_verify(
        tampered, TEST_IMAGE_LEN,
        TEST_PUB_PEM, TEST_PUB_PEM_LEN,
        TEST_AES_KEY);
    TEST_ASSERT_EQUAL_INT(OTA_VERIFY_ERR_MAGIC, e);
}

void test_truncated_header_fails(void)
{
    /* Feed only 10 bytes — less than the 44-byte header */
    ota_verify_ctx_t *ctx = ota_verify_begin(
        TEST_PUB_PEM, TEST_PUB_PEM_LEN, TEST_AES_KEY);
    TEST_ASSERT_NOT_NULL(ctx);

    /* Feed partial header — OK so far */
    ota_verify_err_t e = ota_verify_feed(ctx, TEST_OTA_IMAGE, 10, TEST_IMAGE_LEN);
    TEST_ASSERT_EQUAL_INT(OTA_VERIFY_OK, e);

    /* End prematurely — tail buffer has only 10 bytes, not 64 sig bytes */
    e = ota_verify_end(ctx);
    TEST_ASSERT_EQUAL_INT(OTA_VERIFY_ERR_TRUNCATED, e);
}

void test_image_too_short_rejected_on_feed(void)
{
    /* total_image_len < OTA_HEADER_SIZE + OTA_SIG_LEN + 1 */
    ota_verify_ctx_t *ctx = ota_verify_begin(
        TEST_PUB_PEM, TEST_PUB_PEM_LEN, TEST_AES_KEY);
    TEST_ASSERT_NOT_NULL(ctx);

    uint8_t tiny[10] = {0};
    ota_verify_err_t e = ota_verify_feed(ctx, tiny, 10, 10); /* total=10 < 44+64+1 */
    TEST_ASSERT_EQUAL_INT(OTA_VERIFY_ERR_TRUNCATED, e);
}

void test_wrong_aes_key_fails_tag(void)
{
    /* Wrong AES key — GCM tag will mismatch, but ECDSA also changes because
       ciphertext bytes differ... actually ciphertext same, tag in header same,
       ECDSA covers (header||ciphertext) which is identical, so ECDSA passes,
       then GCM tag check fails with wrong key */
    uint8_t wrong_key[32];
    memcpy(wrong_key, TEST_AES_KEY, 32);
    wrong_key[0] ^= 0xFF;  /* wrong AES key */

    ota_verify_err_t e = run_verify(
        TEST_OTA_IMAGE, TEST_IMAGE_LEN,
        TEST_PUB_PEM, TEST_PUB_PEM_LEN,
        wrong_key);
    /* GCM will produce wrong tag → OTA_VERIFY_ERR_TAG */
    TEST_ASSERT_EQUAL_INT(OTA_VERIFY_ERR_TAG, e);
}

void test_begin_null_key_returns_null(void)
{
    ota_verify_ctx_t *ctx = ota_verify_begin(NULL, 0, TEST_AES_KEY);
    TEST_ASSERT_NULL(ctx);
}

void test_strerror_ok(void)
{
    TEST_ASSERT_EQUAL_STRING("OK", ota_verify_strerror(OTA_VERIFY_OK));
    TEST_ASSERT_EQUAL_STRING("bad magic", ota_verify_strerror(OTA_VERIFY_ERR_MAGIC));
    TEST_ASSERT_EQUAL_STRING("ECDSA signature invalid", ota_verify_strerror(OTA_VERIFY_ERR_SIG));
    TEST_ASSERT_EQUAL_STRING("AES-GCM tag mismatch", ota_verify_strerror(OTA_VERIFY_ERR_TAG));
}

/* ── Main ────────────────────────────────────────────────────────────────── */

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_golden_verifies_ok);
    RUN_TEST(test_golden_verifies_ok_chunked_1byte);
    RUN_TEST(test_golden_verifies_ok_chunked_13bytes);
    RUN_TEST(test_tamper_ciphertext_fails_sig);
    RUN_TEST(test_tamper_signature_fails);
    RUN_TEST(test_wrong_magic_fails);
    RUN_TEST(test_truncated_header_fails);
    RUN_TEST(test_image_too_short_rejected_on_feed);
    RUN_TEST(test_wrong_aes_key_fails_tag);
    RUN_TEST(test_begin_null_key_returns_null);
    RUN_TEST(test_strerror_ok);
    return UNITY_END();
}
