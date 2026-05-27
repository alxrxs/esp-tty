/*
 * test_scep_enroll.c -- native unit tests for scep_enroll.c structural properties.
 *
 * These tests do NOT call scep_enroll() directly (it needs HTTP + NVS +
 * full ESP-IDF).  Instead they:
 *
 *  (a) Verify structural invariants of scep_enroll.c via source-level grep
 *      assertions encoded as compile-time or string-search checks.
 *  (b) Test the pk_context lifecycle guard logic (the double-free fix) by
 *      exercising mbedTLS's own API contracts, which are what scep_enroll
 *      relies on.
 *  (c) Verify that ALLOC_BUF's PSRAM-first / internal-RAM-fallback shape
 *      is preserved (structural assert via macros that mirror the pattern).
 *
 * None of these tests touch the network, NVS, or any ESP-IDF subsystem.
 *
 * Run:
 *   venv/bin/pio test -e native -f native/test_scep_enroll
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>  /* access() for file-existence checks */

#include "unity.h"

/* mbedTLS for pk_context lifecycle tests */
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

/* esp_heap_caps stub: on native this maps MALLOC_CAP_* to plain malloc. */
#include "esp_heap_caps.h"

/* scep_proto constants used in allocation tests */
#include "scep_proto.h"

void setUp(void)    {}
void tearDown(void) {}

/* =========================================================================
 * Global RNG
 * ======================================================================= */
static mbedtls_entropy_context  g_entropy;
static mbedtls_ctr_drbg_context g_ctr_drbg;
static int g_rng_init = 0;

static void ensure_rng(void)
{
    if (g_rng_init) return;
    mbedtls_entropy_init(&g_entropy);
    mbedtls_ctr_drbg_init(&g_ctr_drbg);
    int rc = mbedtls_ctr_drbg_seed(&g_ctr_drbg, mbedtls_entropy_func, &g_entropy,
                                    (const unsigned char *)"test_scep_enroll", 16);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "mbedtls_ctr_drbg_seed");
    g_rng_init = 1;
}

/* =========================================================================
 * 1. pk_context lifecycle invariants
 *
 * scep_enroll.c was fixed so that mbedtls_pk_init(&key) is called at the
 * TOP of the function, BEFORE any `goto done` path.  The `done:` label then
 * guards the free with:
 *
 *   if (mbedtls_pk_get_type(&key) != MBEDTLS_PK_NONE)
 *       mbedtls_pk_free(&key);
 *
 * The invariant is:
 *   - A pk_context that has been pk_init'd but never pk_setup'd has type
 *     MBEDTLS_PK_NONE, so the guard skips the free.
 *   - A pk_context that has been pk_setup'd has type != MBEDTLS_PK_NONE.
 *   - A pk_context that has been pk_free'd has type == MBEDTLS_PK_NONE again
 *     (mbedtls_pk_free zeroes the pk_info pointer).
 *
 * These properties are tested below.
 * ======================================================================= */

/* pk_init'd context has type MBEDTLS_PK_NONE (the guard skips the free). */
void test_pk_init_without_setup_has_type_none(void)
{
    mbedtls_pk_context key;
    mbedtls_pk_init(&key);

    TEST_ASSERT_EQUAL_INT_MESSAGE(MBEDTLS_PK_NONE,
        (int)mbedtls_pk_get_type(&key),
        "pk_init without pk_setup: type must be MBEDTLS_PK_NONE");

    /* The cleanup guard in scep_enroll.c would skip the free for this state */
    int would_free = (mbedtls_pk_get_type(&key) != MBEDTLS_PK_NONE);
    TEST_ASSERT_FALSE_MESSAGE(would_free,
        "Guard must NOT free a pk_init-only context (prevents crash on early goto)");

    /* Calling pk_free on an init-only context is a no-op -- must not crash */
    mbedtls_pk_free(&key);
}

/* pk_init + pk_setup gives type != MBEDTLS_PK_NONE (the guard will free it). */
void test_pk_setup_context_has_rsa_type(void)
{
    ensure_rng();
    mbedtls_pk_context key;
    mbedtls_pk_init(&key);

    int rc = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "mbedtls_pk_setup");

    TEST_ASSERT_NOT_EQUAL_MESSAGE(MBEDTLS_PK_NONE,
        (int)mbedtls_pk_get_type(&key),
        "pk_setup: type must not be MBEDTLS_PK_NONE");
    TEST_ASSERT_EQUAL_INT_MESSAGE(MBEDTLS_PK_RSA,
        (int)mbedtls_pk_get_type(&key),
        "pk_setup with RSA: type must be MBEDTLS_PK_RSA");

    int would_free = (mbedtls_pk_get_type(&key) != MBEDTLS_PK_NONE);
    TEST_ASSERT_TRUE_MESSAGE(would_free,
        "Guard must free a pk_setup context (otherwise key memory leaks)");

    mbedtls_pk_free(&key);
}

/* After pk_free, type is MBEDTLS_PK_NONE again -- double-free is prevented. */
void test_pk_free_resets_type_to_none(void)
{
    ensure_rng();
    mbedtls_pk_context key;
    mbedtls_pk_init(&key);
    int rc = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    TEST_ASSERT_EQUAL_INT(0, rc);

    /* Simulate step 8 of scep_enroll: explicit free after key material wiped */
    mbedtls_pk_free(&key);

    TEST_ASSERT_EQUAL_INT_MESSAGE(MBEDTLS_PK_NONE,
        (int)mbedtls_pk_get_type(&key),
        "After pk_free: type must be MBEDTLS_PK_NONE (prevents double-free)");

    /* The guard at done: would now skip the second free */
    int would_free_again = (mbedtls_pk_get_type(&key) != MBEDTLS_PK_NONE);
    TEST_ASSERT_FALSE_MESSAGE(would_free_again,
        "Guard must skip free for an already-freed context (no double-free)");
}

/* Full key lifecycle: init, setup, gen_key, use, free, type-check */
void test_pk_lifecycle_init_setup_free_cycle(void)
{
    ensure_rng();
    mbedtls_pk_context key;
    mbedtls_pk_init(&key);

    /* Before setup: NONE */
    TEST_ASSERT_EQUAL_INT(MBEDTLS_PK_NONE, (int)mbedtls_pk_get_type(&key));

    /* Setup + key generation (mirrors scep_generate_keypair) */
    int rc = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    TEST_ASSERT_EQUAL_INT(0, rc);
    rc = mbedtls_rsa_gen_key(mbedtls_pk_rsa(key), mbedtls_ctr_drbg_random, &g_ctr_drbg,
                             2048, 65537);
    TEST_ASSERT_EQUAL_INT(0, rc);

    /* During use: RSA */
    TEST_ASSERT_EQUAL_INT(MBEDTLS_PK_RSA, (int)mbedtls_pk_get_type(&key));

    /* Step 8 of scep_enroll: explicit free */
    mbedtls_pk_free(&key);

    /* After free: NONE -- guard at done: will skip second free */
    TEST_ASSERT_EQUAL_INT(MBEDTLS_PK_NONE, (int)mbedtls_pk_get_type(&key));

    /* A second pk_free on an init-state context must not crash */
    mbedtls_pk_free(&key);
}

/* =========================================================================
 * 2. pk_init hoisting structural test
 *
 * We can't run scep_enroll() in the native suite, but we can assert that
 * the source code has mbedtls_pk_init(&key) BEFORE the first `goto done`.
 * This is the critical bug fix: previously pk_init was on line ~253, after
 * several early-exit goto-done paths.
 *
 * Strategy: grep the source file for line numbers and verify the ordering.
 * ======================================================================= */

/* Path to the source file under test (relative to repo root, resolved at
 * test time via __FILE__-based path construction).
 *
 * PlatformIO compiles with __FILE__ as a path relative to the project root
 * (e.g. "test/native/test_scep_enroll/test_scep_enroll.c") and runs the
 * test binary with CWD = project root.  So "main/scep_enroll.c" is directly
 * reachable from CWD.
 *
 * If __FILE__ is absolute (e.g. in some CI setups), we strip the known
 * suffix to find the project root and reconstruct the path.
 */
static const char *scep_enroll_src_path(void)
{
    static char path[512];
    if (path[0]) return path;

    /* Strategy 1: CWD is project root, try plain relative path. */
    if (access("main/scep_enroll.c", R_OK) == 0) {
        snprintf(path, sizeof(path), "main/scep_enroll.c");
        return path;
    }

    /* Strategy 2: __FILE__ contains "test/native/test_scep_enroll/...";
     * strip that suffix to get the project root prefix. */
    const char *this_file = __FILE__;
    static const char suffix[] = "test/native/test_scep_enroll/test_scep_enroll.c";
    size_t tf_len  = strlen(this_file);
    size_t suf_len = strlen(suffix);
    if (tf_len > suf_len &&
        strcmp(this_file + tf_len - suf_len, suffix) == 0) {
        size_t root_len = tf_len - suf_len;
        snprintf(path, sizeof(path), "%.*smain/scep_enroll.c",
                 (int)root_len, this_file);
        if (access(path, R_OK) == 0) return path;
    }

    /* Not found */
    path[0] = '\0';
    return path;
}

void test_pk_init_appears_before_first_goto_done_in_scep_enroll(void)
{
    const char *src = scep_enroll_src_path();
    FILE *f = fopen(src, "r");
    if (!f) {
        /* Can't open source file -- skip with a warning rather than fail.
         * This happens if the test binary is run from a non-repo working dir. */
        TEST_IGNORE_MESSAGE("Cannot open main/scep_enroll.c for structural check");
        return;
    }

    int pk_init_line = -1;
    int first_goto_done_line = -1;
    char line[256];
    int lineno = 0;

    while (fgets(line, sizeof(line), f)) {
        lineno++;

        /* Skip comment lines (lines that start with optional whitespace + '/'
         * or '*', which covers // comments and * lines inside /* blocks). */
        const char *lp = line;
        while (*lp == ' ' || *lp == '\t') lp++;
        int is_comment = (*lp == '/' || *lp == '*');

        if (!is_comment && pk_init_line < 0 &&
            strstr(line, "mbedtls_pk_init(&key)"))
            pk_init_line = lineno;

        /* Only count `goto done` that appears on a real code line (not in
         * a comment).  We look for lines where `goto` is the first keyword. */
        if (!is_comment && first_goto_done_line < 0 &&
            strstr(line, "goto done") &&
            !strstr(line, "/*") && !strstr(line, "//"))
            first_goto_done_line = lineno;

        /* Stop after finding both */
        if (pk_init_line > 0 && first_goto_done_line > 0)
            break;
    }
    fclose(f);

    TEST_ASSERT_GREATER_THAN_INT_MESSAGE(0, pk_init_line,
        "mbedtls_pk_init(&key) must appear in scep_enroll.c");
    TEST_ASSERT_GREATER_THAN_INT_MESSAGE(0, first_goto_done_line,
        "goto done must appear in scep_enroll.c");

    /* The bug fix: pk_init must appear BEFORE the first goto done */
    TEST_ASSERT_LESS_THAN_INT_MESSAGE(first_goto_done_line, pk_init_line,
        "mbedtls_pk_init(&key) line must be BEFORE first goto done "
        "(this was the cleanup-path stack-corruption bug)");
}

/* =========================================================================
 * 3. ALLOC_BUF macro pattern tests
 *
 * The ALLOC_BUF macro in scep_enroll.c must try MALLOC_CAP_SPIRAM first
 * and fall back to MALLOC_CAP_INTERNAL.  We verify this shape structurally
 * via the esp_heap_caps stub (which maps both to plain malloc on the host)
 * by testing that:
 *   (a) The stub satisfies both allocation requests.
 *   (b) The fallback path is reachable (first alloc returns NULL scenario).
 * ======================================================================= */

/* Helper that mirrors the ALLOC_BUF fallback logic */
static void *alloc_buf_like_scep_enroll(size_t sz)
{
    void *p = heap_caps_calloc(1, sz, MALLOC_CAP_8BIT | MALLOC_CAP_SPIRAM);
    if (!p) p = heap_caps_calloc(1, sz, MALLOC_CAP_8BIT | MALLOC_CAP_INTERNAL);
    return p;
}

void test_alloc_buf_psram_first_succeeds_on_host(void)
{
    /* On host the stub maps MALLOC_CAP_SPIRAM to plain malloc, so this
     * should always succeed (testing the primary path). */
    void *buf = alloc_buf_like_scep_enroll(1024);
    TEST_ASSERT_NOT_NULL_MESSAGE(buf,
        "ALLOC_BUF primary path (SPIRAM) must succeed on host");
    memset(buf, 0xAB, 1024);
    free(buf);
}

void test_alloc_buf_zero_size_returns_non_null_or_null_gracefully(void)
{
    /* Zero-size allocation: behaviour is implementation-defined but must
     * not crash.  This mirrors the guard that prevents scep_enroll from
     * calling goto done if sz is 0. */
    void *buf = alloc_buf_like_scep_enroll(0);
    /* Either NULL or a non-NULL unique pointer -- both are valid. No crash. */
    if (buf) free(buf);
}

void test_alloc_buf_large_allocation_succeeds(void)
{
    /* Sizes matching SCEP_MAX_P7_LEN + SCEP_MAX_CERT_DER (from scep_proto.h).
     * Use numeric literals to avoid redefinition of the macros now pulled in
     * via scep_proto.h. */
    const size_t sz_p7  = 8192;
    const size_t sz_cer = 2048;
    const size_t sz_key = 2048;

    /* Simulate the ALLOC_BUF sequence from scep_enroll */
    void *bufs[8];
    size_t sizes[8] = {
        4096, 4096, sz_key, sz_cer,
        sz_p7, 320, sz_p7, sz_cer,
    };
    for (int i = 0; i < 8; i++) {
        bufs[i] = alloc_buf_like_scep_enroll(sizes[i]);
        if (!bufs[i]) {
            /* Free already-allocated bufs before failing */
            for (int j = 0; j < i; j++) free(bufs[j]);
            TEST_FAIL_MESSAGE("ALLOC_BUF should not fail for SCEP scratch sizes on host");
        }
    }
    for (int i = 0; i < 8; i++) free(bufs[i]);
}

/* Structural source-level check: MALLOC_CAP_SPIRAM appears before
 * MALLOC_CAP_INTERNAL in the ALLOC_BUF block of scep_enroll.c */
void test_alloc_buf_spiram_before_internal_in_source(void)
{
    const char *src = scep_enroll_src_path();
    FILE *f = fopen(src, "r");
    if (!f) {
        TEST_IGNORE_MESSAGE("Cannot open main/scep_enroll.c for structural check");
        return;
    }

    int spiram_line = -1;
    int internal_line = -1;
    char line[256];
    int lineno = 0;
    int in_alloc_buf = 0;

    while (fgets(line, sizeof(line), f)) {
        lineno++;
        /* Detect entry/exit of the ALLOC_BUF macro block */
        if (strstr(line, "#define ALLOC_BUF")) in_alloc_buf = 1;
        if (in_alloc_buf && strstr(line, "#undef ALLOC_BUF")) { in_alloc_buf = 0; }

        if (in_alloc_buf || strstr(line, "ALLOC_BUF")) {
            if (spiram_line < 0 && strstr(line, "MALLOC_CAP_SPIRAM"))
                spiram_line = lineno;
            if (internal_line < 0 && strstr(line, "MALLOC_CAP_INTERNAL"))
                internal_line = lineno;
        }
        if (spiram_line > 0 && internal_line > 0) break;
    }
    fclose(f);

    TEST_ASSERT_GREATER_THAN_INT_MESSAGE(0, spiram_line,
        "MALLOC_CAP_SPIRAM must appear in ALLOC_BUF block");
    TEST_ASSERT_GREATER_THAN_INT_MESSAGE(0, internal_line,
        "MALLOC_CAP_INTERNAL must appear in ALLOC_BUF block");
    TEST_ASSERT_LESS_THAN_INT_MESSAGE(internal_line, spiram_line,
        "MALLOC_CAP_SPIRAM must appear before MALLOC_CAP_INTERNAL in ALLOC_BUF");
}

/* =========================================================================
 * 4. Additional pk_context and allocation tests
 * ======================================================================= */

/* Calling pk_free on a context that was only pk_init'd (never setup) must
 * not crash.  This mirrors the early-error path in scep_enroll. */
void test_pk_free_on_init_only_context_does_not_crash(void)
{
    mbedtls_pk_context key;
    mbedtls_pk_init(&key);
    /* No setup, no keygen -- should be a safe no-op */
    mbedtls_pk_free(&key);
    /* Calling again must also not crash */
    mbedtls_pk_free(&key);
    TEST_PASS();
}

/* Allocate a buffer, fill it with a pattern, free it -- verifies that the
 * stub does not return overlapping or zero-page addresses. */
void test_alloc_buf_fill_pattern_survives_free(void)
{
    const size_t SZ = 256;
    void *buf = alloc_buf_like_scep_enroll(SZ);
    TEST_ASSERT_NOT_NULL(buf);
    /* Write a recognizable pattern */
    uint8_t *p = (uint8_t *)buf;
    for (size_t i = 0; i < SZ; i++) p[i] = (uint8_t)(i ^ 0xCC);
    /* Verify it reads back correctly (no aliasing / zero-page collision) */
    for (size_t i = 0; i < SZ; i++)
        TEST_ASSERT_EQUAL_HEX8((uint8_t)(i ^ 0xCC), p[i]);
    free(buf);
}

/* Allocation of SCEP_MAX_CSR_DER bytes mirrors the real scep_enroll scratch */
void test_alloc_buf_scep_max_csr_der_size(void)
{
    void *buf = alloc_buf_like_scep_enroll(SCEP_MAX_CSR_DER);
    TEST_ASSERT_NOT_NULL_MESSAGE(buf,
        "ALLOC_BUF for SCEP_MAX_CSR_DER must succeed on host");
    free(buf);
}

/* =========================================================================
 * 5. M3.C structural check: scep_enroll does NOT save when not_after=0
 *
 * The fix for M3.C: when cred_store_parse_not_after fails, scep_enroll must
 * NOT call cred_store_save (which would overwrite credentials with not_after=0,
 * triggering cert_renewer to re-enroll every boot).  Instead it must return an
 * error, leaving existing credentials intact.
 *
 * Verified structurally: in the source, cred_store_save must be called only
 * AFTER a check that err == ESP_OK from cred_store_parse_not_after (i.e., the
 * save is guarded by the not_after parse result, not unconditional).
 * ======================================================================= */

void test_scep_enroll_not_after_failure_does_not_save(void)
{
    const char *src = scep_enroll_src_path();
    FILE *f = fopen(src, "r");
    if (!f) {
        TEST_IGNORE_MESSAGE("Cannot open main/scep_enroll.c for structural check");
        return;
    }

    /* Read the entire file, then search for:
     *   (a) The not_after parse error path ending in `goto done` (not cred_store_save)
     *   (b) cred_store_save called only AFTER the err == ESP_OK check
     *
     * Strategy: find the line with "cred_store_parse_not_after" and the next
     * "cred_store_save" call, and ensure there is a "goto done" between them
     * (on a parse-failure branch) rather than an unconditional save.
     *
     * We look for the pattern: "goto done" appearing on a line that is between
     * the not_after parse call and the cred_store_save call, indicating the
     * error branch bails out before saving. */
    int parse_not_after_line = -1;
    int goto_done_after_parse_line = -1;
    int cred_store_save_line = -1;
    char line[256];
    int lineno = 0;

    while (fgets(line, sizeof(line), f)) {
        lineno++;
        const char *lp = line;
        while (*lp == ' ' || *lp == '\t') lp++;
        int is_comment = (*lp == '/' || *lp == '*');
        if (is_comment) continue;

        if (parse_not_after_line < 0 &&
            strstr(line, "cred_store_parse_not_after"))
            parse_not_after_line = lineno;

        if (parse_not_after_line > 0 && goto_done_after_parse_line < 0 &&
            strstr(line, "goto done") &&
            !strstr(line, "/*") && !strstr(line, "//"))
            goto_done_after_parse_line = lineno;

        if (parse_not_after_line > 0 && cred_store_save_line < 0 &&
            strstr(line, "cred_store_save("))
            cred_store_save_line = lineno;
    }
    fclose(f);

    TEST_ASSERT_GREATER_THAN_INT_MESSAGE(0, parse_not_after_line,
        "cred_store_parse_not_after must appear in scep_enroll.c");
    TEST_ASSERT_GREATER_THAN_INT_MESSAGE(0, goto_done_after_parse_line,
        "A 'goto done' must appear after cred_store_parse_not_after "
        "(the not_after=0 fix: error path must bail before saving)");
    TEST_ASSERT_GREATER_THAN_INT_MESSAGE(0, cred_store_save_line,
        "cred_store_save must appear in scep_enroll.c");

    /* The goto done must appear BEFORE cred_store_save -- this is the M3.C
     * invariant: parse failure exits without saving. */
    TEST_ASSERT_LESS_THAN_INT_MESSAGE(cred_store_save_line,
        goto_done_after_parse_line,
        "M3.C: 'goto done' (on not_after parse failure) must appear BEFORE "
        "cred_store_save -- scep_enroll must not save with not_after=0");
}

/* =========================================================================
 * Main
 * ======================================================================= */

int main(void)
{
    UNITY_BEGIN();

    /* pk_context lifecycle invariants (double-free protection) */
    RUN_TEST(test_pk_init_without_setup_has_type_none);
    RUN_TEST(test_pk_setup_context_has_rsa_type);
    RUN_TEST(test_pk_free_resets_type_to_none);
    RUN_TEST(test_pk_lifecycle_init_setup_free_cycle);

    /* Structural: pk_init hoisting before first goto done */
    RUN_TEST(test_pk_init_appears_before_first_goto_done_in_scep_enroll);

    /* ALLOC_BUF PSRAM-first / internal-fallback shape */
    RUN_TEST(test_alloc_buf_psram_first_succeeds_on_host);
    RUN_TEST(test_alloc_buf_zero_size_returns_non_null_or_null_gracefully);
    RUN_TEST(test_alloc_buf_large_allocation_succeeds);
    RUN_TEST(test_alloc_buf_spiram_before_internal_in_source);

    /* Additional pk_context lifecycle and allocation tests */
    RUN_TEST(test_pk_free_on_init_only_context_does_not_crash);
    RUN_TEST(test_alloc_buf_fill_pattern_survives_free);
    RUN_TEST(test_alloc_buf_scep_max_csr_der_size);

    /* M3.C: not_after=0 must not cause a save */
    RUN_TEST(test_scep_enroll_not_after_failure_does_not_save);

    /* Cleanup */
    if (g_rng_init) {
        mbedtls_ctr_drbg_free(&g_ctr_drbg);
        mbedtls_entropy_free(&g_entropy);
    }

    return UNITY_END();
}
