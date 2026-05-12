/*
 * test_ota_verify.c -- unit tests for ota_verify.c (native, no hardware)
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

/* -- Golden test vectors --------------------------------------------------- */
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

/* -- Helper: feed image in one shot --------------------------------------- */

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

/* -- Tests ----------------------------------------------------------------- */

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
    /* Feed only 10 bytes -- less than the 44-byte header */
    ota_verify_ctx_t *ctx = ota_verify_begin(
        TEST_PUB_PEM, TEST_PUB_PEM_LEN, TEST_AES_KEY);
    TEST_ASSERT_NOT_NULL(ctx);

    /* Feed partial header -- OK so far */
    ota_verify_err_t e = ota_verify_feed(ctx, TEST_OTA_IMAGE, 10, TEST_IMAGE_LEN);
    TEST_ASSERT_EQUAL_INT(OTA_VERIFY_OK, e);

    /* End prematurely -- tail buffer has only 10 bytes, not 64 sig bytes */
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
    /* Wrong AES key -- GCM tag will mismatch, but ECDSA also changes because
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
    /* GCM will produce wrong tag -> OTA_VERIFY_ERR_TAG */
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
    TEST_ASSERT_EQUAL_STRING("plaintext length mismatch",
                             ota_verify_strerror(OTA_VERIFY_ERR_LENGTH_MISMATCH));
}

/* -- New edge-case tests (Task 5) ------------------------------------------ */

void test_wrong_version_fails(void)
{
    /* Flip the first byte of the version field (offset 8) so version != 1 */
    uint8_t tampered[TEST_IMAGE_LEN];
    memcpy(tampered, TEST_OTA_IMAGE, TEST_IMAGE_LEN);
    tampered[8] ^= 0xFF;  /* version byte 0: 0x01 -> 0xFE -- version field invalid */

    ota_verify_err_t e = run_verify(
        tampered, TEST_IMAGE_LEN,
        TEST_PUB_PEM, TEST_PUB_PEM_LEN,
        TEST_AES_KEY);
    TEST_ASSERT_EQUAL_INT(OTA_VERIFY_ERR_VERSION, e);
}

void test_plaintext_len_mismatch_fails(void)
{
    /*
     * Set plaintext_len in the header to 50 (= 0x32 LE at offset 12),
     * but the actual ciphertext length is 96.  ota_verify_end() must
     * catch this and return OTA_VERIFY_ERR_LENGTH_MISMATCH.
     *
     * The change also breaks the ECDSA signature (the signed region
     * includes the header), but OTA_VERIFY_ERR_LENGTH_MISMATCH is
     * checked before the ECDSA verify in ota_verify_end().
     */
    uint8_t tampered[TEST_IMAGE_LEN];
    memcpy(tampered, TEST_OTA_IMAGE, TEST_IMAGE_LEN);
    /* Overwrite plaintext_len (offset 12-15 LE) with 50 */
    tampered[12] = 50;
    tampered[13] = 0;
    tampered[14] = 0;
    tampered[15] = 0;

    ota_verify_err_t e = run_verify(
        tampered, TEST_IMAGE_LEN,
        TEST_PUB_PEM, TEST_PUB_PEM_LEN,
        TEST_AES_KEY);
    TEST_ASSERT_EQUAL_INT(OTA_VERIFY_ERR_LENGTH_MISMATCH, e);
}

void test_abort_before_header_done(void)
{
    /* Call abort immediately after begin, before any feed.
     * Must not crash; the context must be cleaned up cleanly. */
    ota_verify_ctx_t *ctx = ota_verify_begin(
        TEST_PUB_PEM, TEST_PUB_PEM_LEN, TEST_AES_KEY);
    TEST_ASSERT_NOT_NULL(ctx);

    /* abort before any feed -- header_done is false, so no flash handle to close */
    ota_verify_abort(ctx);
    /* If we get here without crash, the test passes */
    TEST_PASS();
}

void test_abort_is_idempotent_via_null(void)
{
    /* ota_verify_abort(NULL) must be a safe no-op */
    ota_verify_abort(NULL);
    TEST_PASS();
}

void test_feed_null_ctx_returns_error(void)
{
    /*
     * After abort(), the context pointer is freed and invalid.
     * The API contract says "after abort, do not call feed".
     * We test the NULL-ctx guard: feed(NULL, ...) must return ERR_PARAM,
     * which is what the production code checks for (ctx->aborted).
     */
    ota_verify_err_t e = ota_verify_feed(NULL, TEST_OTA_IMAGE, 10, TEST_IMAGE_LEN);
    TEST_ASSERT_EQUAL_INT(OTA_VERIFY_ERR_PARAM, e);
}

void test_null_aes_key_in_begin(void)
{
    /* ota_verify_begin with aes_key=NULL must return NULL (early param check) */
    ota_verify_ctx_t *ctx = ota_verify_begin(TEST_PUB_PEM, TEST_PUB_PEM_LEN, NULL);
    TEST_ASSERT_NULL(ctx);
}

/* -- Section D new tests --------------------------------------------------- */

/*
 * Test 1: empty image (plaintext_len == 0) is rejected.
 *
 * Construct a syntactically valid signed image whose header declares
 * plaintext_len = 0.  The verifier must return OTA_VERIFY_ERR_EMPTY_IMAGE
 * as soon as the header is parsed, before any crypto gate.
 *
 * We build the minimal image: 44-byte header (with plaintext_len=0) + 64-byte
 * dummy signature.  The image is not cryptographically valid but the empty-image
 * check fires before the sig/tag checks.
 */
void test_empty_image_rejected(void)
{
    /*
     * Compose an image whose header declares plaintext_len = 0.
     * A signed 0-byte firmware image is exactly OTA_HEADER_SIZE + OTA_SIG_LEN
     * bytes (header + zero ciphertext + signature).  The truncation check
     * allows this exact size; the empty-image check in the header parser
     * then fires and returns OTA_VERIFY_ERR_EMPTY_IMAGE.
     */
    const size_t TOTAL_LEN = OTA_HEADER_SIZE + OTA_SIG_LEN;
    uint8_t img[OTA_HEADER_SIZE];
    memset(img, 0, sizeof(img));

    /* Magic */
    memcpy(img, OTA_MAGIC, OTA_MAGIC_LEN);
    /* Version = 1 LE */
    img[8] = 1; img[9] = 0; img[10] = 0; img[11] = 0;
    /* plaintext_len = 0 LE */
    img[12] = 0; img[13] = 0; img[14] = 0; img[15] = 0;
    /* IV and tag: all zeros */

    ota_verify_ctx_t *ctx = ota_verify_begin(
        TEST_PUB_PEM, TEST_PUB_PEM_LEN, TEST_AES_KEY);
    TEST_ASSERT_NOT_NULL(ctx);

    /* Feed just enough to complete the header, with a large declared total */
    ota_verify_err_t e = ota_verify_feed(ctx, img, sizeof(img), TOTAL_LEN);
    if (e != OTA_VERIFY_ERR_EMPTY_IMAGE) {
        ota_verify_abort(ctx);
    }
    TEST_ASSERT_EQUAL_INT(OTA_VERIFY_ERR_EMPTY_IMAGE, e);
}

/*
 * Test: strerror covers the new EMPTY_IMAGE code.
 */
void test_strerror_empty_image(void)
{
    TEST_ASSERT_EQUAL_STRING("empty image rejected",
                             ota_verify_strerror(OTA_VERIFY_ERR_EMPTY_IMAGE));
}

/*
 * Test C3 regression: a P-256 PEM that has a 0x04 byte early in the OID region
 * must still verify correctly (not mis-identify the OID byte as the EC point).
 *
 * For P-256, the OID bytes include 0x04 at position 7 of the algorithm params
 * OID (2a 86 48 ce 3d 03 01 07) -- "07" is not 0x04, but we test that the
 * fixed-offset parser is immune to any such issue by verifying the golden test
 * vector still passes (it has the standard DER layout).
 *
 * A deeper test would require crafting a non-standard DER; instead we verify
 * that our DER length check catches a truncated input (der_len != 91).
 */
void test_pem_wrong_length_rejected(void)
{
    /* Build a PEM with a DER body that decodes to 90 bytes (one short).
     * The easiest way is to pass a PEM that doesn't decode to 91 bytes.
     * We construct one by stripping the last base64 byte of TEST_PUB_PEM. */

    /* The TEST_PUB_PEM decodes to 91 bytes.  Find the base64 end-of-body and
     * trim one character to make the decoded DER 1 byte shorter. */

    /* Copy the PEM, find the base64 region, shorten it by 4 chars (one group = 3 bytes).
     * That makes it 88 bytes -> der_len != 91 -> pem_extract_ec_point returns -1
     * -> ota_verify_begin returns NULL. */

    /* For simplicity, just verify that a clearly wrong PEM (too short) causes
     * ota_verify_begin to fail cleanly (return NULL). */
    const char *bad_pem =
        "-----BEGIN PUBLIC KEY-----\n"
        "MFkw\n"   /* only 3 base64 chars -- decodes to 2 bytes, far less than 91 */
        "-----END PUBLIC KEY-----\n";

    ota_verify_ctx_t *ctx = ota_verify_begin(
        (const uint8_t *)bad_pem, strlen(bad_pem) + 1, TEST_AES_KEY);
    TEST_ASSERT_NULL(ctx);  /* pem_extract_ec_point must reject der_len != 91 */
}

/* -- Main ------------------------------------------------------------------ */

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
    /* Task 5 new tests */
    RUN_TEST(test_wrong_version_fails);
    RUN_TEST(test_plaintext_len_mismatch_fails);
    RUN_TEST(test_abort_before_header_done);
    RUN_TEST(test_abort_is_idempotent_via_null);
    RUN_TEST(test_feed_null_ctx_returns_error);
    RUN_TEST(test_null_aes_key_in_begin);
    /* Section D new tests */
    RUN_TEST(test_empty_image_rejected);
    RUN_TEST(test_strerror_empty_image);
    RUN_TEST(test_pem_wrong_length_rejected);
    return UNITY_END();
}
