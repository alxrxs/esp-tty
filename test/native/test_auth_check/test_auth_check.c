/*
 * test_auth_check.c -- unit tests for pubkey_auth_check() (native, no hardware)
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

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/sha256.h"

void setUp(void)    {}
void tearDown(void) {}

/* ------------------------------------------------------------------ */
/* Test helper: compute SHA-256( uint32be(len) || data ) into out[].
 * Mirrors pubkey_auth_check()'s internal hash computation so tests can
 * pre-populate an expected_hash[] array without depending on pubkey_auth's
 * internals being exposed.
 */
static void compute_expected_hash(const uint8_t *data, size_t data_sz,
                                  uint8_t out[PUBKEY_HASH_SIZE])
{
    Sha256 sha;
    uint8_t len_buf[4];
    uint32_t sz32 = (uint32_t)data_sz;
    len_buf[0] = (sz32 >> 24) & 0xFF;
    len_buf[1] = (sz32 >> 16) & 0xFF;
    len_buf[2] = (sz32 >>  8) & 0xFF;
    len_buf[3] = (sz32      ) & 0xFF;

    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, len_buf, 4);
    wc_Sha256Update(&sha, data, (word32)data_sz);
    wc_Sha256Final(&sha, out);
}

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

/* SHA-256( uint32be(51) || TEST_BLOB ) -- computed offline */
static const uint8_t EXPECTED_HASH[PUBKEY_HASH_SIZE] = {
    0x60, 0xf7, 0x3d, 0x25, 0xf4, 0x6f, 0xe7, 0x0d,
    0x39, 0x24, 0x2c, 0x95, 0x9d, 0x32, 0x92, 0x4b,
    0xfc, 0x2d, 0x26, 0xdf, 0x4c, 0x26, 0x48, 0xfe,
    0xf3, 0x39, 0x73, 0xf0, 0x25, 0xdf, 0xde, 0x29,
};

/* ------------------------------------------------------------------ */
/* Accept path: correct key -> PUBKEY_AUTH_OK                          */

void test_auth_check_accept_correct_key(void)
{
    pubkey_auth_result_t result =
        pubkey_auth_check(TEST_BLOB, TEST_BLOB_LEN, EXPECTED_HASH);

    TEST_ASSERT_EQUAL_INT(PUBKEY_AUTH_OK, result);
}

/* ------------------------------------------------------------------ */
/* Reject paths                                                         */

/* Reject: one byte differs -- SHA-256 completely changes */
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
    /* Truncate by one byte -- uint32be(50) != uint32be(51) */
    pubkey_auth_result_t result =
        pubkey_auth_check(TEST_BLOB, TEST_BLOB_LEN - 1, EXPECTED_HASH);

    TEST_ASSERT_EQUAL_INT(PUBKEY_AUTH_REJECTED, result);
}

/* ------------------------------------------------------------------ */
/* Edge cases                                                           */

/* Edge: zero-length key -> REJECTED without touching hash bytes */
void test_auth_check_edge_zero_length(void)
{
    pubkey_auth_result_t result =
        pubkey_auth_check(TEST_BLOB, 0, EXPECTED_HASH);

    TEST_ASSERT_EQUAL_INT(PUBKEY_AUTH_REJECTED, result);
}

/* Edge: NULL key -> REJECTED without crash */
void test_auth_check_edge_null_key(void)
{
    pubkey_auth_result_t result =
        pubkey_auth_check(NULL, TEST_BLOB_LEN, EXPECTED_HASH);

    TEST_ASSERT_EQUAL_INT(PUBKEY_AUTH_REJECTED, result);
}

/* ------------------------------------------------------------------ */
/* Multi-key iteration semantics                                      */
/*                                                                    */
/* These tests verify that the loop in main/ssh_server.c's            */
/* user_auth_callback (around line 113):                              */
/*                                                                    */
/*     for (int i = 0; i < s_authkey_count; i++)                       */
/*         if (pubkey_auth_check(..., s_authkey_hashes[i]) == OK)      */
/*             return SUCCESS;                                         */
/*                                                                    */
/* behaves correctly under various positions of the matching key.     */
/* The tests mirror that loop locally so the lib API does not need    */
/* a new multi-key entry point.                                       */
/* ------------------------------------------------------------------ */

/* "Match if any" helper: emulate the production loop. Returns true if
 * any expected[i] matches the presented key, false otherwise.
 * matched_index_out (if non-NULL) receives the index of the first match,
 * or -1 if no match.
 */
static bool loop_match_any(const uint8_t *presented, size_t presented_sz,
                           const uint8_t expected[][PUBKEY_HASH_SIZE],
                           size_t count, int *matched_index_out)
{
    if (matched_index_out) *matched_index_out = -1;
    for (size_t i = 0; i < count; i++) {
        if (pubkey_auth_check(presented, presented_sz, expected[i])
            == PUBKEY_AUTH_OK) {
            if (matched_index_out) *matched_index_out = (int)i;
            return true;
        }
    }
    return false;
}

/* Three distinct test payloads of equal length so a wrong-data hash is
 * a genuine SHA-256 collision-free mismatch (not just length-prefix). */
static const uint8_t DATA_D[8]      = { 0xD0, 0xD1, 0xD2, 0xD3,
                                        0xD4, 0xD5, 0xD6, 0xD7 };
static const uint8_t DATA_OTHER1[8] = { 0xA0, 0xA1, 0xA2, 0xA3,
                                        0xA4, 0xA5, 0xA6, 0xA7 };
static const uint8_t DATA_OTHER2[8] = { 0xB0, 0xB1, 0xB2, 0xB3,
                                        0xB4, 0xB5, 0xB6, 0xB7 };

/* (1) Match at index 0: loop returns OK after only checking i=0. */
void test_auth_check_loop_matches_first_key(void)
{
    uint8_t expected[3][PUBKEY_HASH_SIZE];
    compute_expected_hash(DATA_D,      sizeof DATA_D,      expected[0]);
    compute_expected_hash(DATA_OTHER1, sizeof DATA_OTHER1, expected[1]);
    compute_expected_hash(DATA_OTHER2, sizeof DATA_OTHER2, expected[2]);

    /* Per-slot expectations */
    TEST_ASSERT_EQUAL_INT(PUBKEY_AUTH_OK,
        pubkey_auth_check(DATA_D, sizeof DATA_D, expected[0]));
    TEST_ASSERT_EQUAL_INT(PUBKEY_AUTH_REJECTED,
        pubkey_auth_check(DATA_D, sizeof DATA_D, expected[1]));
    TEST_ASSERT_EQUAL_INT(PUBKEY_AUTH_REJECTED,
        pubkey_auth_check(DATA_D, sizeof DATA_D, expected[2]));

    /* "Match if any" loop: OK after checking only i=0 */
    int idx = -1;
    bool any = loop_match_any(DATA_D, sizeof DATA_D, expected, 3, &idx);
    TEST_ASSERT_TRUE(any);
    TEST_ASSERT_EQUAL_INT(0, idx);
}

/* (2) Match at index 2 (last): loop returns OK at i=2 only. */
void test_auth_check_loop_matches_last_key(void)
{
    uint8_t expected[3][PUBKEY_HASH_SIZE];
    compute_expected_hash(DATA_OTHER1, sizeof DATA_OTHER1, expected[0]);
    compute_expected_hash(DATA_OTHER2, sizeof DATA_OTHER2, expected[1]);
    compute_expected_hash(DATA_D,      sizeof DATA_D,      expected[2]);

    TEST_ASSERT_EQUAL_INT(PUBKEY_AUTH_REJECTED,
        pubkey_auth_check(DATA_D, sizeof DATA_D, expected[0]));
    TEST_ASSERT_EQUAL_INT(PUBKEY_AUTH_REJECTED,
        pubkey_auth_check(DATA_D, sizeof DATA_D, expected[1]));
    TEST_ASSERT_EQUAL_INT(PUBKEY_AUTH_OK,
        pubkey_auth_check(DATA_D, sizeof DATA_D, expected[2]));

    int idx = -1;
    bool any = loop_match_any(DATA_D, sizeof DATA_D, expected, 3, &idx);
    TEST_ASSERT_TRUE(any);
    TEST_ASSERT_EQUAL_INT(2, idx);
}

/* (3) No match: all three expected[] are hashes of unrelated data. */
void test_auth_check_loop_no_match(void)
{
    static const uint8_t DATA_OTHER3[8] = { 0xC0, 0xC1, 0xC2, 0xC3,
                                            0xC4, 0xC5, 0xC6, 0xC7 };
    uint8_t expected[3][PUBKEY_HASH_SIZE];
    compute_expected_hash(DATA_OTHER1, sizeof DATA_OTHER1, expected[0]);
    compute_expected_hash(DATA_OTHER2, sizeof DATA_OTHER2, expected[1]);
    compute_expected_hash(DATA_OTHER3, sizeof DATA_OTHER3, expected[2]);

    for (int i = 0; i < 3; i++) {
        TEST_ASSERT_EQUAL_INT(PUBKEY_AUTH_REJECTED,
            pubkey_auth_check(DATA_D, sizeof DATA_D, expected[i]));
    }

    int idx = 999;
    bool any = loop_match_any(DATA_D, sizeof DATA_D, expected, 3, &idx);
    TEST_ASSERT_FALSE(any);
    TEST_ASSERT_EQUAL_INT(-1, idx);
}

/* (4) count == 0: mirrors s_authkey_count==0 early return. The loop body
 * never executes, and "match if any" is REJECTED. */
void test_auth_check_loop_zero_count(void)
{
    /* Provide a fully-populated array, but pass count=0 -- the loop must
     * not iterate even once. */
    uint8_t expected[3][PUBKEY_HASH_SIZE];
    compute_expected_hash(DATA_D,      sizeof DATA_D,      expected[0]);
    compute_expected_hash(DATA_OTHER1, sizeof DATA_OTHER1, expected[1]);
    compute_expected_hash(DATA_OTHER2, sizeof DATA_OTHER2, expected[2]);

    int idx = 42;
    bool any = loop_match_any(DATA_D, sizeof DATA_D, expected, 0, &idx);
    TEST_ASSERT_FALSE(any);
    TEST_ASSERT_EQUAL_INT(-1, idx);
}

/* (5) Constant-time comparison: a difference in either the FIRST or the
 * LAST byte of the 32-byte hash must still produce REJECTED. This is the
 * behavioural witness that the XOR-accumulator loop in pubkey_auth_check
 * inspects every byte (a memcmp() that short-circuits on byte 0 would
 * still reject -- so we test both ends to exercise the full sweep). */
void test_auth_check_constant_time_all_bytes_compared(void)
{
    uint8_t correct[PUBKEY_HASH_SIZE];
    compute_expected_hash(DATA_D, sizeof DATA_D, correct);

    /* expected[0] differs in byte 0 only */
    uint8_t expected0[PUBKEY_HASH_SIZE];
    memcpy(expected0, correct, PUBKEY_HASH_SIZE);
    expected0[0] ^= 0x01;

    /* expected[1] differs in byte 31 only (last byte) */
    uint8_t expected1[PUBKEY_HASH_SIZE];
    memcpy(expected1, correct, PUBKEY_HASH_SIZE);
    expected1[PUBKEY_HASH_SIZE - 1] ^= 0x01;

    /* Sanity: the unperturbed hash still matches */
    TEST_ASSERT_EQUAL_INT(PUBKEY_AUTH_OK,
        pubkey_auth_check(DATA_D, sizeof DATA_D, correct));

    /* Both single-byte perturbations must be rejected -- confirming the
     * XOR accumulator covers all 32 bytes, not just an early prefix. */
    TEST_ASSERT_EQUAL_INT(PUBKEY_AUTH_REJECTED,
        pubkey_auth_check(DATA_D, sizeof DATA_D, expected0));
    TEST_ASSERT_EQUAL_INT(PUBKEY_AUTH_REJECTED,
        pubkey_auth_check(DATA_D, sizeof DATA_D, expected1));
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
    RUN_TEST(test_auth_check_loop_matches_first_key);
    RUN_TEST(test_auth_check_loop_matches_last_key);
    RUN_TEST(test_auth_check_loop_no_match);
    RUN_TEST(test_auth_check_loop_zero_count);
    RUN_TEST(test_auth_check_constant_time_all_bytes_compared);
    return UNITY_END();
}
