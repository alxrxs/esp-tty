/*
 * test_pubkey_auth.c — unit tests for pubkey_auth.c (native, no hardware)
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

/* SHA-256( uint32be(51) || 51-byte-blob ) — computed offline */
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
    /* Pubkey without trailing comment — must still work */
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
 * Segments are 76 characters each (9 × 76 = 684).
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
 * Segments are 76 characters each (9 × 76 = 684).
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

/* SHA-256( uint32be(512) || 0x42*512 ) — computed offline with Python */
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
    return UNITY_END();
}
