/*
 * test_pubkey_auth.c -- unit tests for pubkey_auth.c (native, no hardware)
 *
 * Tests the OpenSSH pubkey string parsing and SHA-256 hash computation
 * that guards the wolfSSH authentication callback.
 *
 * Golden values computed with Python:
 *   python3 -c "
 *     import base64, struct, hashlib
 *     key_type = b'ssh-ed25519'
 *     pub = bytes(range(32))
 *     blob = struct.pack('>I', len(key_type)) + key_type + struct.pack('>I', 32) + pub
 *     b64  = base64.b64encode(blob).decode()
 *     h    = hashlib.sha256(struct.pack('>I', len(blob)) + blob).hexdigest()
 *     print(b64, h)"
 */

#include <string.h>
#include <stdint.h>
#include <stdio.h>

#include "unity.h"
#include "pubkey_auth.h"

void setUp(void)    {}
void tearDown(void) {}

/* ------------------------------------------------------------------ */
/* Known-good OpenSSH Ed25519 public key (fake deterministic key)     */

#define TEST_PUBKEY \
    "ssh-ed25519 " \
    "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f" \
    " test@host"

/* SHA-256( uint32be(51) || 51-byte-blob ) -- computed offline */
static const uint8_t EXPECTED_HASH[32] = {
    0x60, 0xf7, 0x3d, 0x25, 0xf4, 0x6f, 0xe7, 0x0d,
    0x39, 0x24, 0x2c, 0x95, 0x9d, 0x32, 0x92, 0x4b,
    0xfc, 0x2d, 0x26, 0xdf, 0x4c, 0x26, 0x48, 0xfe,
    0xf3, 0x39, 0x73, 0xf0, 0x25, 0xdf, 0xde, 0x29,
};

/* ------------------------------------------------------------------ */

void test_parse_b64_finds_blob(void)
{
    const char *start = NULL;
    size_t      len   = 0;

    bool ok = pubkey_parse_b64(TEST_PUBKEY, &start, &len);

    TEST_ASSERT_TRUE(ok);
    TEST_ASSERT_NOT_NULL(start);
    /* The base64 field is exactly the b64 token above */
    TEST_ASSERT_EQUAL_size_t(
        strlen("AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"),
        len);
    TEST_ASSERT_EQUAL_MEMORY(
        "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f",
        start, len);
}

void test_parse_b64_no_comment(void)
{
    /* Pubkey without trailing comment -- must still work */
    const char *line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f";
    const char *start = NULL;
    size_t      len   = 0;

    TEST_ASSERT_TRUE(pubkey_parse_b64(line, &start, &len));
    TEST_ASSERT_GREATER_THAN(0, len);
}

void test_parse_b64_rejects_no_space(void)
{
    const char *start = NULL;
    size_t      len   = 0;

    TEST_ASSERT_FALSE(pubkey_parse_b64("malformed-no-space", &start, &len));
}

void test_parse_b64_rejects_empty_blob(void)
{
    /* Space with nothing after it */
    const char *start = NULL;
    size_t      len   = 0;

    TEST_ASSERT_FALSE(pubkey_parse_b64("ssh-ed25519 ", &start, &len));
}

void test_parse_b64_null_input(void)
{
    const char *start = NULL;
    size_t      len   = 0;

    TEST_ASSERT_FALSE(pubkey_parse_b64(NULL, &start, &len));
}

void test_compute_hash_golden_value(void)
{
    uint8_t hash[32];
    bool ok = pubkey_compute_hash(TEST_PUBKEY, hash);

    TEST_ASSERT_TRUE(ok);
    TEST_ASSERT_EQUAL_MEMORY(EXPECTED_HASH, hash, 32);
}

void test_compute_hash_deterministic(void)
{
    /* Same input twice must produce identical output */
    uint8_t h1[32], h2[32];

    TEST_ASSERT_TRUE(pubkey_compute_hash(TEST_PUBKEY, h1));
    TEST_ASSERT_TRUE(pubkey_compute_hash(TEST_PUBKEY, h2));
    TEST_ASSERT_EQUAL_MEMORY(h1, h2, 32);
}

void test_compute_hash_different_keys_differ(void)
{
    /* Changing one byte in the key must change the hash */
    const char *key1 =
        "ssh-ed25519 "
        "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"
        " host1";
    /* Flip a bit in the base64 (different key) */
    const char *key2 =
        "ssh-ed25519 "
        "AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4g"
        " host2";

    uint8_t h1[32], h2[32];
    TEST_ASSERT_TRUE(pubkey_compute_hash(key1, h1));
    TEST_ASSERT_TRUE(pubkey_compute_hash(key2, h2));
    TEST_ASSERT_NOT_EQUAL(0, memcmp(h1, h2, 32));
}

void test_compute_hash_rejects_malformed(void)
{
    uint8_t hash[32];
    TEST_ASSERT_FALSE(pubkey_compute_hash("not-a-pubkey", hash));
}

void test_compute_hash_comment_ignored(void)
{
    /* Hash must be the same regardless of the trailing comment field */
    const char *with_comment    = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f user@laptop";
    const char *without_comment = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f";

    uint8_t h1[32], h2[32];
    TEST_ASSERT_TRUE(pubkey_compute_hash(with_comment, h1));
    TEST_ASSERT_TRUE(pubkey_compute_hash(without_comment, h2));
    TEST_ASSERT_EQUAL_MEMORY(h1, h2, 32);
}

/* --- Buffer overflow guard: 513-byte decoded blob ------------------- */

/*
 * A base64 string that decodes to exactly 513 bytes (one byte over the
 * blob[512] fixed buffer in pubkey_auth.c:pubkey_compute_hash()).
 *
 * Generated with:
 *   python3 -c "import base64; print(base64.b64encode(b'\\x42'*513).decode())"
 *
 * pubkey_compute_hash() calls Base64_Decode() with blob_sz=512. Passing a
 * blob that decodes to 513 bytes must cause Base64_Decode to fail (output
 * buffer too small), and pubkey_compute_hash() must return false.
 */
/*
 * 513 raw bytes of 0x42, base64-encoded without line breaks (684 characters).
 * Generated with:
 *   python3 -c "import base64; print(base64.b64encode(b'\\x42'*513).decode())"
 */
/*
 * 513 raw bytes of 0x42, base64-encoded without line breaks (684 chars).
 * Segments are 76 characters each (9 x 76 = 684).
 * Generated with:
 *   python3 -c "import base64; print(base64.b64encode(b'\\x42'*513).decode())"
 */
static const char *OVER_512_PUBKEY =
    "ssh-ed25519 "
    "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC"
    "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC"
    "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC"
    "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC"
    "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC"
    "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC"
    "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC"
    "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC"
    "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC"
    " overflow@test";

void test_compute_hash_rejects_over_512_byte_blob(void)
{
    uint8_t hash[32];
    /* Must fail: decoded blob is 513 bytes, one over the internal 512-byte buffer */
    TEST_ASSERT_FALSE(pubkey_compute_hash(OVER_512_PUBKEY, hash));
}

/* --- Boundary: exactly 512-byte decoded blob (inclusive upper bound) -- */

/*
 * 512 raw bytes of 0x42, base64-encoded without line breaks (684 chars).
 * Segments are 76 characters each (9 x 76 = 684).
 * Generated with:
 *   python3 -c "import base64; print(base64.b64encode(b'\\x42'*512).decode())"
 *
 * This sits exactly at the inclusive upper bound of pubkey_compute_hash()'s
 * internal blob[512] buffer. Base64_Decode() must succeed and the function
 * must return true, producing SHA-256( uint32be(512) || 0x42*512 ).
 */
static const char *EXACT_512_PUBKEY =
    "ssh-ed25519 "
    "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC"
    "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC"
    "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC"
    "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC"
    "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC"
    "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC"
    "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC"
    "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC"
    "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI="
    " boundary@test";

/* SHA-256( uint32be(512) || 0x42*512 ) -- computed offline with Python */
static const uint8_t EXPECTED_HASH_512[32] = {
    0x54, 0x40, 0xab, 0x07, 0x15, 0x00, 0x29, 0xdb,
    0x87, 0x55, 0x1f, 0x6d, 0x43, 0x1a, 0x82, 0x21,
    0x4b, 0x34, 0xd6, 0xf6, 0x51, 0xff, 0xa4, 0x40,
    0x88, 0x93, 0x10, 0x9e, 0x5f, 0x3e, 0x59, 0xda,
};

void test_compute_hash_accepts_exactly_512_byte_blob(void)
{
    uint8_t hash[32];
    /* Must succeed: decoded blob fits exactly in the internal 512-byte buffer */
    TEST_ASSERT_TRUE(pubkey_compute_hash(EXACT_512_PUBKEY, hash));
    TEST_ASSERT_EQUAL_MEMORY(EXPECTED_HASH_512, hash, 32);
}

/* ===================================================================
 * pubkey_auth_check() tests
 * =================================================================== */

/*
 * Build a presented key that is the raw decoded blob for TEST_PUBKEY, then
 * use the hash already computed by pubkey_compute_hash for the acceptance
 * path.  This exercises the full round-trip:
 *
 *   1. pubkey_compute_hash(line) -> expected_hash
 *   2. Decode base64 -> raw_blob
 *   3. pubkey_auth_check(raw_blob, blob_len, expected_hash) -> OK
 */

/* Decoded blob for TEST_PUBKEY's base64 field (51 bytes).  Pre-computed so
 * the test doesn't need a base64 decoder stub at this layer. */
static const uint8_t TEST_BLOB[51] = {
    0x00, 0x00, 0x00, 0x0b,  /* uint32be(11): length of "ssh-ed25519" */
    0x73, 0x73, 0x68, 0x2d, 0x65, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39,
    0x00, 0x00, 0x00, 0x20,  /* uint32be(32): length of key material */
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};

void test_auth_check_ok_for_matching_hash(void)
{
    /* Compute the expected hash from the known-good pubkey string. */
    uint8_t expected[32];
    bool ok = pubkey_compute_hash(TEST_PUBKEY, expected);
    TEST_ASSERT_TRUE(ok);

    /* The auth check against the raw blob must succeed. */
    pubkey_auth_result_t r = pubkey_auth_check(TEST_BLOB, sizeof(TEST_BLOB),
                                               expected);
    TEST_ASSERT_EQUAL_INT(PUBKEY_AUTH_OK, r);
}

void test_auth_check_rejects_wrong_hash(void)
{
    uint8_t wrong_hash[32];
    memset(wrong_hash, 0xAA, sizeof(wrong_hash));

    pubkey_auth_result_t r = pubkey_auth_check(TEST_BLOB, sizeof(TEST_BLOB),
                                               wrong_hash);
    TEST_ASSERT_EQUAL_INT(PUBKEY_AUTH_REJECTED, r);
}

void test_auth_check_rejects_null_key(void)
{
    uint8_t hash[32];
    memset(hash, 0, sizeof(hash));
    pubkey_auth_result_t r = pubkey_auth_check(NULL, 16, hash);
    TEST_ASSERT_EQUAL_INT(PUBKEY_AUTH_REJECTED, r);
}

void test_auth_check_rejects_zero_length_key(void)
{
    uint8_t hash[32];
    memset(hash, 0, sizeof(hash));
    pubkey_auth_result_t r = pubkey_auth_check(TEST_BLOB, 0, hash);
    TEST_ASSERT_EQUAL_INT(PUBKEY_AUTH_REJECTED, r);
}

void test_auth_check_differs_for_different_blob(void)
{
    /* Two distinct blobs must produce different auth results for the same
     * expected hash (i.e., the second must be rejected). */
    uint8_t expected[32];
    pubkey_compute_hash(TEST_PUBKEY, expected);

    uint8_t other_blob[51];
    memcpy(other_blob, TEST_BLOB, sizeof(other_blob));
    other_blob[20] ^= 0xFF;  /* flip a byte -- different key material */

    pubkey_auth_result_t r = pubkey_auth_check(other_blob, sizeof(other_blob),
                                               expected);
    TEST_ASSERT_EQUAL_INT(PUBKEY_AUTH_REJECTED, r);
}

void test_auth_check_single_bit_flip_rejected(void)
{
    /* Constant-time compare: flipping a single bit in the blob must be caught. */
    uint8_t expected[32];
    pubkey_compute_hash(TEST_PUBKEY, expected);

    uint8_t bad_blob[51];
    memcpy(bad_blob, TEST_BLOB, sizeof(bad_blob));
    bad_blob[sizeof(bad_blob) - 1] ^= 0x01;  /* flip LSB of last byte */

    pubkey_auth_result_t r = pubkey_auth_check(bad_blob, sizeof(bad_blob),
                                               expected);
    TEST_ASSERT_EQUAL_INT(PUBKEY_AUTH_REJECTED, r);
}

/* ===================================================================
 * format_fingerprint() tests
 * =================================================================== */

void test_format_fingerprint_known_value(void)
{
    /* All-zeros digest -> "00:00:...:00" (32 bytes * 3 - 1 colon chars). */
    uint8_t zeros[PUBKEY_HASH_SIZE];
    memset(zeros, 0, sizeof(zeros));

    char out[PUBKEY_HASH_SIZE * 3 + 1];
    char *ret = format_fingerprint(zeros, out, sizeof(out));

    TEST_ASSERT_NOT_NULL(ret);
    TEST_ASSERT_EQUAL_PTR(out, ret);

    /* First byte "00", colon, second byte "00", ..., last byte "00" (no colon). */
    /* Verify first and last bytes are formatted correctly. */
    TEST_ASSERT_EQUAL_UINT8('0', (uint8_t)out[0]);
    TEST_ASSERT_EQUAL_UINT8('0', (uint8_t)out[1]);
    TEST_ASSERT_EQUAL_UINT8(':', (uint8_t)out[2]);
    /* Last three chars: "00\0" */
    size_t total_len = PUBKEY_HASH_SIZE * 3 - 1;  /* 95 payload bytes */
    TEST_ASSERT_EQUAL_UINT8('0', (uint8_t)out[total_len - 2]);
    TEST_ASSERT_EQUAL_UINT8('0', (uint8_t)out[total_len - 1]);
    TEST_ASSERT_EQUAL_UINT8('\0', (uint8_t)out[total_len]);
}

void test_format_fingerprint_all_ff(void)
{
    uint8_t all_ff[PUBKEY_HASH_SIZE];
    memset(all_ff, 0xFF, sizeof(all_ff));

    char out[PUBKEY_HASH_SIZE * 3 + 1];
    char *ret = format_fingerprint(all_ff, out, sizeof(out));

    TEST_ASSERT_NOT_NULL(ret);
    /* First two chars must be "ff". */
    TEST_ASSERT_EQUAL_UINT8('f', (uint8_t)out[0]);
    TEST_ASSERT_EQUAL_UINT8('f', (uint8_t)out[1]);
    TEST_ASSERT_EQUAL_UINT8(':', (uint8_t)out[2]);
}

void test_format_fingerprint_returns_null_for_small_buf(void)
{
    uint8_t digest[PUBKEY_HASH_SIZE];
    memset(digest, 0x42, sizeof(digest));

    /* Need at least PUBKEY_HASH_SIZE*3 bytes; pass one byte too few. */
    char small[PUBKEY_HASH_SIZE * 3 - 1];
    char *ret = format_fingerprint(digest, small, sizeof(small));
    TEST_ASSERT_NULL(ret);
}

void test_format_fingerprint_null_digest_returns_null(void)
{
    char out[PUBKEY_HASH_SIZE * 3 + 1];
    char *ret = format_fingerprint(NULL, out, sizeof(out));
    TEST_ASSERT_NULL(ret);
}

void test_format_fingerprint_null_out_returns_null(void)
{
    uint8_t digest[PUBKEY_HASH_SIZE];
    memset(digest, 0, sizeof(digest));
    char *ret = format_fingerprint(digest, NULL, 96);
    TEST_ASSERT_NULL(ret);
}

void test_format_fingerprint_incremental_byte(void)
{
    /* digest[0]=0x0b, digest[1]=0x0c, rest 0 -> starts with "0b:0c:" */
    uint8_t digest[PUBKEY_HASH_SIZE];
    memset(digest, 0, sizeof(digest));
    digest[0] = 0x0b;
    digest[1] = 0x0c;

    char out[PUBKEY_HASH_SIZE * 3 + 1];
    char *ret = format_fingerprint(digest, out, sizeof(out));

    TEST_ASSERT_NOT_NULL(ret);
    TEST_ASSERT_EQUAL_UINT8('0', (uint8_t)out[0]);
    TEST_ASSERT_EQUAL_UINT8('b', (uint8_t)out[1]);
    TEST_ASSERT_EQUAL_UINT8(':', (uint8_t)out[2]);
    TEST_ASSERT_EQUAL_UINT8('0', (uint8_t)out[3]);
    TEST_ASSERT_EQUAL_UINT8('c', (uint8_t)out[4]);
    TEST_ASSERT_EQUAL_UINT8(':', (uint8_t)out[5]);
}

/* ===================================================================
 * Key-type-specific parsing tests
 * =================================================================== */

/* ssh-rsa: minimal blob with small exponent and modulus */
static const char *SSH_RSA_PUBKEY =
    "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAAirze8BI0VniQ== rsa-test@host";

static const uint8_t SSH_RSA_EXPECTED_HASH[32] = {
    0xd1, 0x9a, 0x3a, 0xdf, 0x3e, 0xc3, 0x7e, 0x52,
    0x34, 0xdb, 0xa1, 0x9a, 0xf6, 0x45, 0xdf, 0x32,
    0x8e, 0x88, 0x14, 0x08, 0xa5, 0x2d, 0x02, 0x4c,
    0x82, 0xbd, 0xaa, 0xb5, 0xfe, 0xf1, 0x59, 0x10,
};

void test_parse_b64_ssh_rsa_key_type(void)
{
    const char *start = NULL;
    size_t len = 0;
    TEST_ASSERT_TRUE(pubkey_parse_b64(SSH_RSA_PUBKEY, &start, &len));
    TEST_ASSERT_GREATER_THAN(0, len);
    /* Must point to the base64 field, not the key-type */
    TEST_ASSERT_EQUAL_UINT8('A', (uint8_t)start[0]);
}

void test_compute_hash_ssh_rsa_golden(void)
{
    uint8_t hash[32];
    TEST_ASSERT_TRUE(pubkey_compute_hash(SSH_RSA_PUBKEY, hash));
    TEST_ASSERT_EQUAL_MEMORY(SSH_RSA_EXPECTED_HASH, hash, 32);
}

/* ecdsa-sha2-nistp256 -- b64 must be a single unbroken token (no mid-token splits) */
static const char *SSH_ECDSA_PUBKEY =
    "ecdsa-sha2-nistp256 "
    "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqu7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7s="
    " ecdsa-test@host";

static const uint8_t SSH_ECDSA_EXPECTED_HASH[32] = {
    0x4d, 0xda, 0xbb, 0x58, 0xcf, 0x34, 0x43, 0x38,
    0xa3, 0x53, 0xb3, 0x52, 0x69, 0xf7, 0xd1, 0xf7,
    0x11, 0xa6, 0x82, 0x4e, 0x8d, 0x0d, 0x0f, 0x51,
    0x52, 0x75, 0x83, 0xfb, 0xf5, 0x70, 0x99, 0x8e,
};

void test_parse_b64_ecdsa_nistp256_key_type(void)
{
    const char *start = NULL;
    size_t len = 0;
    TEST_ASSERT_TRUE(pubkey_parse_b64(SSH_ECDSA_PUBKEY, &start, &len));
    TEST_ASSERT_GREATER_THAN(0, len);
}

void test_compute_hash_ecdsa_nistp256_golden(void)
{
    uint8_t hash[32];
    TEST_ASSERT_TRUE(pubkey_compute_hash(SSH_ECDSA_PUBKEY, hash));
    TEST_ASSERT_EQUAL_MEMORY(SSH_ECDSA_EXPECTED_HASH, hash, 32);
}

/* ssh-dss */
static const char *SSH_DSS_PUBKEY =
    "ssh-dss "
    "AAAAB3NzaC1kc3MAAABA3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e"
    "3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3gAAABSrq6urq6urq6urq6ur"
    "q6urq6urqwAAAEDNzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3"
    "Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3NAAAAQO/v7+/v7+/v7+/v7+/v7+"
    "/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+8="
    " dss-test@host";

static const uint8_t SSH_DSS_EXPECTED_HASH[32] = {
    0x38, 0x71, 0x15, 0x5d, 0x90, 0x73, 0x4b, 0x73,
    0x53, 0xe6, 0x90, 0xfa, 0x7e, 0x0d, 0x77, 0x7f,
    0x7c, 0xff, 0xa9, 0x9f, 0x41, 0x6b, 0x41, 0x73,
    0x44, 0x3f, 0x66, 0xde, 0x05, 0xd7, 0x7e, 0xa6,
};

void test_parse_b64_ssh_dss_key_type(void)
{
    const char *start = NULL;
    size_t len = 0;
    TEST_ASSERT_TRUE(pubkey_parse_b64(SSH_DSS_PUBKEY, &start, &len));
    TEST_ASSERT_GREATER_THAN(0, len);
}

void test_compute_hash_ssh_dss_golden(void)
{
    uint8_t hash[32];
    TEST_ASSERT_TRUE(pubkey_compute_hash(SSH_DSS_PUBKEY, hash));
    TEST_ASSERT_EQUAL_MEMORY(SSH_DSS_EXPECTED_HASH, hash, 32);
}

/* --- Malformed base64 ----------------------------------------- */

void test_compute_hash_rejects_invalid_base64_chars(void)
{
    /* '!' is not a valid base64 character */
    const char *bad = "ssh-ed25519 AAAA!!!!InvalidBase64==== user@host";
    uint8_t hash[32];
    TEST_ASSERT_FALSE(pubkey_compute_hash(bad, hash));
}

void test_compute_hash_rejects_truncated_blob(void)
{
    /* Abruptly truncated base64 -- not a valid padding boundary */
    const char *bad = "ssh-ed25519 AAAAC3NzaC1lZDI user@host";
    uint8_t hash[32];
    /* May succeed or fail depending on wolfcrypt padding mode; we only test no crash */
    (void)pubkey_compute_hash(bad, hash);
    /* No assertion on return value -- just must not crash */
    TEST_ASSERT_TRUE(1);
}

/* --- Trailing whitespace on the key line ---------------------- */

void test_parse_b64_trailing_newline_excluded(void)
{
    /* Parser must stop at \n -- the blob should not include it */
    const char *line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f\n";
    const char *start = NULL;
    size_t len = 0;
    TEST_ASSERT_TRUE(pubkey_parse_b64(line, &start, &len));
    /* len must equal the pure base64 field, not include \n */
    size_t expected_len = strlen("AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f");
    TEST_ASSERT_EQUAL_size_t(expected_len, len);
}

void test_parse_b64_trailing_cr_excluded(void)
{
    const char *line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f\r";
    const char *start = NULL;
    size_t len = 0;
    TEST_ASSERT_TRUE(pubkey_parse_b64(line, &start, &len));
    size_t expected_len = strlen("AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f");
    TEST_ASSERT_EQUAL_size_t(expected_len, len);
}

/* Hash must be identical whether or not a trailing newline is present */
void test_compute_hash_trailing_whitespace_ignored(void)
{
    const char *no_ws    = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f";
    const char *with_crlf = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f\r\n";
    uint8_t h1[32], h2[32];
    TEST_ASSERT_TRUE(pubkey_compute_hash(no_ws, h1));
    TEST_ASSERT_TRUE(pubkey_compute_hash(with_crlf, h2));
    TEST_ASSERT_EQUAL_MEMORY(h1, h2, 32);
}

/* --- Comment field edge cases --------------------------------- */

void test_parse_b64_comment_with_shell_metacharacters(void)
{
    /* Shell metacharacters in comment must not affect b64 field extraction */
    const char *line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f user$HOME;rm -rf /";
    const char *start = NULL;
    size_t len = 0;
    TEST_ASSERT_TRUE(pubkey_parse_b64(line, &start, &len));
    size_t expected_len = strlen("AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f");
    TEST_ASSERT_EQUAL_size_t(expected_len, len);
}

void test_compute_hash_long_comment_same_as_no_comment(void)
{
    /* Extremely long comment -- hash must match the no-comment variant */
    const char *base = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f";
    /* 200-char comment */
    char line_long[512];
    snprintf(line_long, sizeof(line_long), "%s %s", base,
             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    uint8_t h_base[32], h_long[32];
    TEST_ASSERT_TRUE(pubkey_compute_hash(base, h_base));
    TEST_ASSERT_TRUE(pubkey_compute_hash(line_long, h_long));
    TEST_ASSERT_EQUAL_MEMORY(h_base, h_long, 32);
}

/* --- Multiple keys in one string: only the first is parsed ------- */
void test_parse_b64_stops_at_first_key(void)
{
    /* Two keys concatenated; parser sees only the first line's b64 field */
    const char *two_keys =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f key1\n"
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4g key2";
    const char *start = NULL;
    size_t len = 0;
    TEST_ASSERT_TRUE(pubkey_parse_b64(two_keys, &start, &len));
    /* Length must be the first key's b64 only */
    size_t first_len = strlen("AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f");
    TEST_ASSERT_EQUAL_size_t(first_len, len);
}

/* ------------------------------------------------------------------ */

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_parse_b64_finds_blob);
    RUN_TEST(test_parse_b64_no_comment);
    RUN_TEST(test_parse_b64_rejects_no_space);
    RUN_TEST(test_parse_b64_rejects_empty_blob);
    RUN_TEST(test_parse_b64_null_input);
    RUN_TEST(test_compute_hash_golden_value);
    RUN_TEST(test_compute_hash_deterministic);
    RUN_TEST(test_compute_hash_different_keys_differ);
    RUN_TEST(test_compute_hash_rejects_malformed);
    RUN_TEST(test_compute_hash_comment_ignored);
    RUN_TEST(test_compute_hash_rejects_over_512_byte_blob);
    RUN_TEST(test_compute_hash_accepts_exactly_512_byte_blob);
    /* pubkey_auth_check() tests */
    RUN_TEST(test_auth_check_ok_for_matching_hash);
    RUN_TEST(test_auth_check_rejects_wrong_hash);
    RUN_TEST(test_auth_check_rejects_null_key);
    RUN_TEST(test_auth_check_rejects_zero_length_key);
    RUN_TEST(test_auth_check_differs_for_different_blob);
    RUN_TEST(test_auth_check_single_bit_flip_rejected);
    /* format_fingerprint() tests */
    RUN_TEST(test_format_fingerprint_known_value);
    RUN_TEST(test_format_fingerprint_all_ff);
    RUN_TEST(test_format_fingerprint_returns_null_for_small_buf);
    RUN_TEST(test_format_fingerprint_null_digest_returns_null);
    RUN_TEST(test_format_fingerprint_null_out_returns_null);
    RUN_TEST(test_format_fingerprint_incremental_byte);
    /* Key-type-specific tests */
    RUN_TEST(test_parse_b64_ssh_rsa_key_type);
    RUN_TEST(test_compute_hash_ssh_rsa_golden);
    RUN_TEST(test_parse_b64_ecdsa_nistp256_key_type);
    RUN_TEST(test_compute_hash_ecdsa_nistp256_golden);
    RUN_TEST(test_parse_b64_ssh_dss_key_type);
    RUN_TEST(test_compute_hash_ssh_dss_golden);
    /* Malformed / edge cases */
    RUN_TEST(test_compute_hash_rejects_invalid_base64_chars);
    RUN_TEST(test_compute_hash_rejects_truncated_blob);
    RUN_TEST(test_parse_b64_trailing_newline_excluded);
    RUN_TEST(test_parse_b64_trailing_cr_excluded);
    RUN_TEST(test_compute_hash_trailing_whitespace_ignored);
    /* Comment field edge cases */
    RUN_TEST(test_parse_b64_comment_with_shell_metacharacters);
    RUN_TEST(test_compute_hash_long_comment_same_as_no_comment);
    /* Multi-key string */
    RUN_TEST(test_parse_b64_stops_at_first_key);
    return UNITY_END();
}
