/*
 * test_auth_check.c — unit tests for pubkey_auth_check() (native, no hardware)
 *
 * pubkey_auth_check() is the pure helper extracted from ssh_server.c's
 * user_auth_callback so the auth logic can be tested without wolfSSH,
 * a live socket, or a FreeRTOS task.
 *
 * Golden vector: the same TEST_PUBKEY / EXPECTED_HASH as test_pubkey_auth.c.
 * The 68-byte b64 string decodes to a 51-byte OpenSSH Ed25519 blob.
 * EXPECTED_HASH = SHA-256( uint32be(51) || blob ).
 */

#include <string.h>
#include <stdint.h>
#include <stdio.h>

#include "unity.h"
#include "pubkey_auth.h"

void setUp(void)    {}
void tearDown(void) {}

/* ------------------------------------------------------------------ */
/* Golden test vector (matches test_pubkey_auth.c)                    */

/*
 * 51-byte decoded blob for:
 *   ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f
 */
static const uint8_t TEST_BLOB[51] = {
    0x00, 0x00, 0x00, 0x0b, 0x73, 0x73, 0x68, 0x2d, 0x65, 0x64, 0x32,
    0x35, 0x35, 0x31, 0x39, 0x00, 0x00, 0x00, 0x20, 0x00, 0x01, 0x02,
    0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
    0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};
#define TEST_BLOB_LEN  sizeof(TEST_BLOB)

/* SHA-256( uint32be(51) || TEST_BLOB ) — computed offline */
static const uint8_t EXPECTED_HASH[PUBKEY_HASH_SIZE] = {
    0x60, 0xf7, 0x3d, 0x25, 0xf4, 0x6f, 0xe7, 0x0d,
    0x39, 0x24, 0x2c, 0x95, 0x9d, 0x32, 0x92, 0x4b,
    0xfc, 0x2d, 0x26, 0xdf, 0x4c, 0x26, 0x48, 0xfe,
    0xf3, 0x39, 0x73, 0xf0, 0x25, 0xdf, 0xde, 0x29,
};

/* ------------------------------------------------------------------ */
/* Accept path: correct key → PUBKEY_AUTH_OK                          */

void test_auth_check_accept_correct_key(void)
{
    pubkey_auth_result_t result =
        pubkey_auth_check(TEST_BLOB, TEST_BLOB_LEN, EXPECTED_HASH);

    TEST_ASSERT_EQUAL_INT(PUBKEY_AUTH_OK, result);
}

/* ------------------------------------------------------------------ */
/* Reject paths                                                         */

/* Reject: one byte differs — SHA-256 completely changes */
void test_auth_check_reject_one_byte_changed(void)
{
    uint8_t bad_blob[TEST_BLOB_LEN];
    memcpy(bad_blob, TEST_BLOB, TEST_BLOB_LEN);
    bad_blob[25] ^= 0xFF;  /* flip a byte in the key material */

    pubkey_auth_result_t result =
        pubkey_auth_check(bad_blob, TEST_BLOB_LEN, EXPECTED_HASH);

    TEST_ASSERT_EQUAL_INT(PUBKEY_AUTH_REJECTED, result);
}

/* Reject: same bytes but different length (hash includes length prefix) */
void test_auth_check_reject_different_length(void)
{
    /* Truncate by one byte — uint32be(50) ≠ uint32be(51) */
    pubkey_auth_result_t result =
        pubkey_auth_check(TEST_BLOB, TEST_BLOB_LEN - 1, EXPECTED_HASH);

    TEST_ASSERT_EQUAL_INT(PUBKEY_AUTH_REJECTED, result);
}

/* ------------------------------------------------------------------ */
/* Edge cases                                                           */

/* Edge: zero-length key → REJECTED without touching hash bytes */
void test_auth_check_edge_zero_length(void)
{
    pubkey_auth_result_t result =
        pubkey_auth_check(TEST_BLOB, 0, EXPECTED_HASH);

    TEST_ASSERT_EQUAL_INT(PUBKEY_AUTH_REJECTED, result);
}

/* Edge: NULL key → REJECTED without crash */
void test_auth_check_edge_null_key(void)
{
    pubkey_auth_result_t result =
        pubkey_auth_check(NULL, TEST_BLOB_LEN, EXPECTED_HASH);

    TEST_ASSERT_EQUAL_INT(PUBKEY_AUTH_REJECTED, result);
}

/* ------------------------------------------------------------------ */

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_auth_check_accept_correct_key);
    RUN_TEST(test_auth_check_reject_one_byte_changed);
    RUN_TEST(test_auth_check_reject_different_length);
    RUN_TEST(test_auth_check_edge_zero_length);
    RUN_TEST(test_auth_check_edge_null_key);
    return UNITY_END();
}
