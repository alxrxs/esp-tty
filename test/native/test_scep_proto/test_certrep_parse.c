/*
 * test_certrep_parse.c -- behavioural native tests for scep_parse_certrep()
 *
 * These tests build a REAL, correctly-signed SUCCESS CertRep pkiMessage in C
 * (SignedData( EnvelopedData( degenerate-SignedData( cert ) ) ), RFC 8894
 * §4.3) and then feed pristine and surgically-mutated variants to the
 * production parser lib/scep_proto/scep_proto.c::scep_parse_certrep().
 *
 * Because scep_parse_certrep verifies the OUTER SignedData signature over the
 * signedAttrs before doing anything else, every variant is built with a valid
 * signature; the negative cases mutate fields that are NOT covered by that
 * signature (the EnvelopedData content) or omit/retag signed attributes and
 * re-sign, so the parser actually reaches the inner check under test.
 *
 * Coverage (audit findings F1-F5):
 *   - VALID CertRep round-trips: issued cert is recovered           (no regression)
 *   - transactionID signed attribute absent           -> rejected   (F3)
 *   - encryptedContent length not a multiple of 16     -> rejected   (F2)
 *   - EnvelopedData SEQUENCE replaced with EOC (0x00)  -> rejected   (F5)
 *   - signedAttrs [0] retagged as EOC (0x00)           -> rejected   (F4)
 *
 * The CEK-wipe-on-all-paths fix (F1) cannot be observed directly from a unit
 * test (there is no portable way to inspect a wiped stack slot), but every
 * negative case below drives scep_parse_certrep down an early-return path that
 * the fix re-routes through the single CEK-zeroizing cleanup label; the valid
 * case exercises the success path's zeroize.  So all CEK-wipe exit paths are
 * executed here even though the wipe itself is not asserted.
 *
 * Run:
 *   venv/bin/pio test -e native -f native/test_scep_proto
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "mbedtls/build_info.h"   /* MBEDTLS_VERSION_NUMBER */
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/sha256.h"
#include "mbedtls/aes.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/asn1.h"
#include "mbedtls/asn1write.h"

#include "unity.h"
#include "scep_proto.h"

/*
 * NOTE: setUp()/tearDown()/main() and the shared RNG live in
 * test_scep_proto.c -- PlatformIO compiles every .c in this directory into a
 * single test suite, so those symbols must be defined exactly once.  This
 * file only adds the CertRep-parsing test cases; they are registered from the
 * main() in test_scep_proto.c via certrep_register_tests().
 *
 * To keep the two translation units independent, this file owns its own
 * CTR-DRBG (file-static, distinct symbols).
 */

/* ========================================================================= */
/* RNG (file-static -- distinct from test_scep_proto.c's RNG)                */
/* ========================================================================= */

static mbedtls_entropy_context  cr_entropy;
static mbedtls_ctr_drbg_context cr_ctr_drbg;
static int cr_rng_init = 0;

static void ensure_rng(void)
{
    if (cr_rng_init) return;
    mbedtls_entropy_init(&cr_entropy);
    mbedtls_ctr_drbg_init(&cr_ctr_drbg);
    int rc = mbedtls_ctr_drbg_seed(&cr_ctr_drbg, mbedtls_entropy_func, &cr_entropy,
                                   (const unsigned char *)"test_certrep", 12);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "mbedtls_ctr_drbg_seed");
    cr_rng_init = 1;
}

/* ========================================================================= */
/* OID byte arrays (content only -- same encoding scep_proto.c uses)         */
/* ========================================================================= */

static const uint8_t OID_SIGNED_DATA[]    = {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x02};
static const uint8_t OID_DATA[]           = {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x01};
static const uint8_t OID_ENVELOPED_DATA[] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x03};
static const uint8_t OID_RSA_ENCRYPTION[] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01};
static const uint8_t OID_SHA256_WITH_RSA[]= {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x0b};
static const uint8_t OID_SHA256[]         = {0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01};
static const uint8_t OID_AES256_CBC[]     = {0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x2a};
static const uint8_t OID_MSG_TYPE[]   = {0x60,0x86,0x48,0x01,0x86,0xf8,0x45,0x01,0x09,0x02};
static const uint8_t OID_PKI_STATUS[] = {0x60,0x86,0x48,0x01,0x86,0xf8,0x45,0x01,0x09,0x03};
static const uint8_t OID_TXID[]       = {0x60,0x86,0x48,0x01,0x86,0xf8,0x45,0x01,0x09,0x07};

#define IV_LEN  16
#define CEK_LEN 32
#define SHA256_LEN 32

#define TEST_TXID "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

/* ========================================================================= */
/* Backwards-write ASN.1 helpers (mbedtls asn1write convention)              */
/* ========================================================================= */

#define CK(expr) do { int _r = (expr); if (_r < 0) return _r; len += _r; } while (0)

/* Write SEQUENCE { ...body already written... } wrapping `len` bytes. */
static int wrap_tag(uint8_t **p, uint8_t *start, size_t inner_len, uint8_t tag)
{
    int len = 0;
    CK(mbedtls_asn1_write_len(p, start, inner_len));
    CK(mbedtls_asn1_write_tag(p, start, tag));
    return len;
}

/*
 * Build a degenerate (cert-only) SignedData ContentInfo (RFC 5652 §5.1) into
 * the END of `buf`.  On success sets *out_der (into buf) and *out_len and
 * returns the total length (>0); returns negative on buffer overflow.  This is
 * a standalone function so CK()'s early-return semantics leak nothing.
 */
static int build_inner_degenerate(uint8_t *buf, size_t bufsz,
                                  const uint8_t *cert, size_t cert_len,
                                  const uint8_t **out_der, size_t *out_len)
{
    uint8_t *p = buf + bufsz;
    int len = 0;
    /* signerInfos SET (empty) */
    CK(wrap_tag(&p, buf, 0, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET));
    /* certificates [0] IMPLICIT { cert } */
    CK(mbedtls_asn1_write_raw_buffer(&p, buf, cert, cert_len));
    CK(mbedtls_asn1_write_len(&p, buf, cert_len));
    CK(mbedtls_asn1_write_tag(&p, buf, 0xA0));
    /* encapContentInfo SEQUENCE { OID data } */
    {
        int el = 0;
        el += mbedtls_asn1_write_raw_buffer(&p, buf, OID_DATA, sizeof(OID_DATA));
        el += mbedtls_asn1_write_len(&p, buf, sizeof(OID_DATA));
        el += mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_OID);
        el += mbedtls_asn1_write_len(&p, buf, (size_t)el);
        el += mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        len += el;
    }
    /* digestAlgorithms SET (empty) */
    CK(wrap_tag(&p, buf, 0, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET));
    /* version INTEGER 1 */
    CK(mbedtls_asn1_write_int(&p, buf, 1));
    /* SignedData SEQUENCE */
    CK(wrap_tag(&p, buf, (size_t)len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
    /* [0] EXPLICIT */
    CK(wrap_tag(&p, buf, (size_t)len, 0xA0));
    /* OID signedData */
    CK(mbedtls_asn1_write_raw_buffer(&p, buf, OID_SIGNED_DATA, sizeof(OID_SIGNED_DATA)));
    CK(mbedtls_asn1_write_len(&p, buf, sizeof(OID_SIGNED_DATA)));
    CK(mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_OID));
    /* ContentInfo SEQUENCE */
    CK(wrap_tag(&p, buf, (size_t)len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
    *out_der = p;
    *out_len = (size_t)len;
    return len;
}

/* ========================================================================= */
/* CertRep builder                                                            */
/* ========================================================================= */

/*
 * Knobs that select which (post-signature) defect to inject.  A value of 0
 * means "build the field correctly".
 */
typedef struct {
    int omit_txid;          /* F3: drop the transactionID signed attribute   */
    int unaligned_content;  /* F2: make encryptedContent length not %16 == 0 */
    int env_tag_eoc;        /* F5: replace EnvelopedData SEQUENCE tag w/ 0x00 */
    int sa_tag_eoc;         /* F4: replace signedAttrs [0] tag w/ EOC 0x00    */
} certrep_defects_t;

/*
 * Build a SUCCESS CertRep.  On success returns a malloc'd DER buffer in
 * *out (caller frees) and its length in *out_len.  *recip_key receives the
 * recipient (device) private key the parser must use to decrypt; caller frees
 * it with mbedtls_pk_free.  Returns 0 on success, negative on failure.
 */
static int build_certrep(const certrep_defects_t *def,
                         uint8_t **out, size_t *out_len,
                         mbedtls_pk_context *recip_key)
{
    ensure_rng();

    int ret = -1;
    uint8_t *result = NULL;

    /* ---- keys + certs --------------------------------------------------- */
    mbedtls_pk_context ra_key;   mbedtls_pk_init(&ra_key);
    mbedtls_pk_init(recip_key);

    static uint8_t ra_cert[2048];   size_t ra_cert_len = sizeof(ra_cert);
    static uint8_t issued[2048];    size_t issued_len  = sizeof(issued);

    if (scep_generate_keypair(&ra_key, mbedtls_ctr_drbg_random, &cr_ctr_drbg) != 0) goto cleanup;
    if (scep_generate_keypair(recip_key, mbedtls_ctr_drbg_random, &cr_ctr_drbg) != 0) goto cleanup;

    {
        scep_subject_t ra_subj = { .common_name = "Test SCEP RA" };
        if (scep_build_self_signed_cert(&ra_subj, &ra_key,
                                        mbedtls_ctr_drbg_random, &cr_ctr_drbg,
                                        ra_cert, &ra_cert_len) != 0) goto cleanup;
        /* The "issued" cert is the leaf the CA would hand back; here we just
         * reuse the recipient key self-signed -- only its DER shape matters. */
        scep_subject_t leaf_subj = { .common_name = "issued-device" };
        if (scep_build_self_signed_cert(&leaf_subj, recip_key,
                                        mbedtls_ctr_drbg_random, &cr_ctr_drbg,
                                        issued, &issued_len) != 0) goto cleanup;
    }

    /* Pull RA cert pubkey (for KTRI recipient) and serial/issuer-ish data.   */
    mbedtls_x509_crt recip_crt; mbedtls_x509_crt_init(&recip_crt);

    /* The recipient cert is the device's own self-signed cert: build it. */
    static uint8_t recip_cert[2048]; size_t recip_cert_len = sizeof(recip_cert);
    {
        scep_subject_t rsubj = { .common_name = "device-recipient" };
        if (scep_build_self_signed_cert(&rsubj, recip_key,
                                        mbedtls_ctr_drbg_random, &cr_ctr_drbg,
                                        recip_cert, &recip_cert_len) != 0) {
            mbedtls_x509_crt_free(&recip_crt);
            goto cleanup;
        }
        if (mbedtls_x509_crt_parse_der(&recip_crt, recip_cert, recip_cert_len) != 0) {
            mbedtls_x509_crt_free(&recip_crt);
            goto cleanup;
        }
    }

    /* ---- inner degenerate SignedData (just the issued cert in certs[0]) -- */
    uint8_t inner_buf[4096];
    const uint8_t *inner_der = NULL;
    size_t inner_total = 0;
    if (build_inner_degenerate(inner_buf, sizeof(inner_buf), issued, issued_len,
                               &inner_der, &inner_total) < 0) {
        mbedtls_x509_crt_free(&recip_crt);
        goto cleanup;
    }

    /* ---- AES-256-CBC encrypt the inner degenerate SignedData ------------ */
    uint8_t cek[CEK_LEN], iv[IV_LEN];
    mbedtls_ctr_drbg_random(&cr_ctr_drbg, cek, CEK_LEN);
    mbedtls_ctr_drbg_random(&cr_ctr_drbg, iv, IV_LEN);

    /* PKCS#7 pad to 16 */
    size_t plain_len = inner_total;
    size_t pad = 16 - (plain_len % 16);
    size_t padded_len = plain_len + pad;
    uint8_t *padded = malloc(padded_len);
    if (!padded) { mbedtls_x509_crt_free(&recip_crt); goto cleanup; }
    memcpy(padded, inner_der, plain_len);
    for (size_t i = 0; i < pad; i++) padded[plain_len + i] = (uint8_t)pad;

    uint8_t *ct = malloc(padded_len);
    if (!ct) { free(padded); mbedtls_x509_crt_free(&recip_crt); goto cleanup; }
    {
        mbedtls_aes_context aes; mbedtls_aes_init(&aes);
        uint8_t iv2[IV_LEN]; memcpy(iv2, iv, IV_LEN);
        mbedtls_aes_setkey_enc(&aes, cek, 256);
        mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded_len, iv2, padded, ct);
        mbedtls_aes_free(&aes);
    }
    free(padded);

    size_t ct_len = padded_len;
    /* F2: corrupt the ciphertext length so it is no longer block-aligned by
     * dropping one byte (the parser must reject before touching the cipher). */
    if (def->unaligned_content && ct_len > 1) ct_len -= 1;

    /* ---- RSA-encrypt CEK to recipient (PKCS#1 v1.5) --------------------- */
    mbedtls_rsa_context *recip_rsa = mbedtls_pk_rsa(recip_crt.pk);
    size_t rsa_len = mbedtls_rsa_get_len(recip_rsa);
    uint8_t *enc_cek = malloc(rsa_len);
    if (!enc_cek) { free(ct); mbedtls_x509_crt_free(&recip_crt); goto cleanup; }
    mbedtls_rsa_set_padding(recip_rsa, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE);
    if (mbedtls_rsa_pkcs1_encrypt(recip_rsa, mbedtls_ctr_drbg_random, &cr_ctr_drbg,
                                  CEK_LEN, cek, enc_cek) != 0) {
        free(enc_cek); free(ct); mbedtls_x509_crt_free(&recip_crt); goto cleanup;
    }
    mbedtls_x509_crt_free(&recip_crt);

    /* ---- Build EnvelopedData ContentInfo -------------------------------- */
    uint8_t env_buf[6144];
    uint8_t *evp = env_buf + sizeof(env_buf);
    size_t env_total;
    {
        int len = 0;

        /* encryptedContentInfo SEQUENCE { OID data, contentEncAlg, [0] ct } */
        int eci_len = 0;
        {
            int l = 0;
            /* encryptedContent [0] IMPLICIT (primitive) */
            l += mbedtls_asn1_write_raw_buffer(&evp, env_buf, ct, ct_len);
            l += mbedtls_asn1_write_len(&evp, env_buf, ct_len);
            l += mbedtls_asn1_write_tag(&evp, env_buf, 0x80); /* [0] primitive */
            /* contentEncryptionAlgorithm SEQUENCE { OID aes256-cbc, IV } */
            {
                int al = 0;
                al += mbedtls_asn1_write_raw_buffer(&evp, env_buf, iv, IV_LEN);
                al += mbedtls_asn1_write_len(&evp, env_buf, IV_LEN);
                al += mbedtls_asn1_write_tag(&evp, env_buf, MBEDTLS_ASN1_OCTET_STRING);
                al += mbedtls_asn1_write_raw_buffer(&evp, env_buf, OID_AES256_CBC, sizeof(OID_AES256_CBC));
                al += mbedtls_asn1_write_len(&evp, env_buf, sizeof(OID_AES256_CBC));
                al += mbedtls_asn1_write_tag(&evp, env_buf, MBEDTLS_ASN1_OID);
                al += mbedtls_asn1_write_len(&evp, env_buf, (size_t)al);
                al += mbedtls_asn1_write_tag(&evp, env_buf,
                        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
                l += al;
            }
            /* contentType OID data */
            l += mbedtls_asn1_write_raw_buffer(&evp, env_buf, OID_DATA, sizeof(OID_DATA));
            l += mbedtls_asn1_write_len(&evp, env_buf, sizeof(OID_DATA));
            l += mbedtls_asn1_write_tag(&evp, env_buf, MBEDTLS_ASN1_OID);
            l += mbedtls_asn1_write_len(&evp, env_buf, (size_t)l);
            l += mbedtls_asn1_write_tag(&evp, env_buf,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
            eci_len = l;
        }
        len += eci_len;

        /* recipientInfos SET { KTRI } */
        {
            int sl = 0;
            int ktri = 0;
            /* encryptedKey OCTET STRING */
            ktri += mbedtls_asn1_write_raw_buffer(&evp, env_buf, enc_cek, rsa_len);
            ktri += mbedtls_asn1_write_len(&evp, env_buf, rsa_len);
            ktri += mbedtls_asn1_write_tag(&evp, env_buf, MBEDTLS_ASN1_OCTET_STRING);
            /* keyEncryptionAlgorithm SEQUENCE { OID rsaEncryption, NULL } */
            {
                int al = 0;
                al += mbedtls_asn1_write_null(&evp, env_buf);
                al += mbedtls_asn1_write_raw_buffer(&evp, env_buf, OID_RSA_ENCRYPTION, sizeof(OID_RSA_ENCRYPTION));
                al += mbedtls_asn1_write_len(&evp, env_buf, sizeof(OID_RSA_ENCRYPTION));
                al += mbedtls_asn1_write_tag(&evp, env_buf, MBEDTLS_ASN1_OID);
                al += mbedtls_asn1_write_len(&evp, env_buf, (size_t)al);
                al += mbedtls_asn1_write_tag(&evp, env_buf,
                        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
                ktri += al;
            }
            /* rid: issuerAndSerialNumber SEQUENCE { SEQUENCE{} (issuer), INTEGER 1 } */
            {
                int rl = 0;
                rl += mbedtls_asn1_write_int(&evp, env_buf, 1);          /* serial */
                rl += wrap_tag(&evp, env_buf, 0,
                        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE); /* issuer Name (empty) */
                rl += mbedtls_asn1_write_len(&evp, env_buf, (size_t)rl);
                rl += mbedtls_asn1_write_tag(&evp, env_buf,
                        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
                ktri += rl;
            }
            /* version INTEGER 0 */
            ktri += mbedtls_asn1_write_int(&evp, env_buf, 0);
            /* KTRI SEQUENCE */
            ktri += mbedtls_asn1_write_len(&evp, env_buf, (size_t)ktri);
            ktri += mbedtls_asn1_write_tag(&evp, env_buf,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
            /* recipientInfos SET */
            sl = ktri;
            sl += mbedtls_asn1_write_len(&evp, env_buf, (size_t)sl);
            sl += mbedtls_asn1_write_tag(&evp, env_buf,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET);
            len += sl;
        }

        /* version INTEGER 0 */
        len += mbedtls_asn1_write_int(&evp, env_buf, 0);

        /* EnvelopedData SEQUENCE */
        len += mbedtls_asn1_write_len(&evp, env_buf, (size_t)len);
        {
            uint8_t ed_tag = MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE;
            if (def->env_tag_eoc) ed_tag = 0x00; /* F5: EOC instead of SEQUENCE */
            len += mbedtls_asn1_write_tag(&evp, env_buf, ed_tag);
        }

        /* [0] EXPLICIT */
        len += mbedtls_asn1_write_len(&evp, env_buf, (size_t)len);
        len += mbedtls_asn1_write_tag(&evp, env_buf, 0xA0);
        /* OID envelopedData */
        len += mbedtls_asn1_write_raw_buffer(&evp, env_buf, OID_ENVELOPED_DATA, sizeof(OID_ENVELOPED_DATA));
        len += mbedtls_asn1_write_len(&evp, env_buf, sizeof(OID_ENVELOPED_DATA));
        len += mbedtls_asn1_write_tag(&evp, env_buf, MBEDTLS_ASN1_OID);
        /* ContentInfo SEQUENCE */
        len += mbedtls_asn1_write_len(&evp, env_buf, (size_t)len);
        len += mbedtls_asn1_write_tag(&evp, env_buf,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        env_total = (size_t)len;
    }
    const uint8_t *env_der = evp;
    free(enc_cek);
    free(ct);

    /* ---- Build signed attributes --------------------------------------- */
    /* Each attribute: SEQUENCE { OID, SET { value } }.  We collect them, sort,
     * then assemble the [0] IMPLICIT content (and a SET-tagged copy to sign). */
    struct { uint8_t buf[128]; size_t len; } attr[3];
    memset(attr, 0, sizeof(attr));
    int nattr = 0;

    /* messageType "3" (CertRep) */
    {
        static const uint8_t v[] = {0x13, 0x01, '3'};
        uint8_t *a = attr[nattr].buf + sizeof(attr[nattr].buf); int len = 0;
        len += mbedtls_asn1_write_raw_buffer(&a, attr[nattr].buf, v, sizeof(v));
        len += mbedtls_asn1_write_len(&a, attr[nattr].buf, sizeof(v));
        len += mbedtls_asn1_write_tag(&a, attr[nattr].buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET);
        len += mbedtls_asn1_write_raw_buffer(&a, attr[nattr].buf, OID_MSG_TYPE, sizeof(OID_MSG_TYPE));
        len += mbedtls_asn1_write_len(&a, attr[nattr].buf, sizeof(OID_MSG_TYPE));
        len += mbedtls_asn1_write_tag(&a, attr[nattr].buf, MBEDTLS_ASN1_OID);
        len += mbedtls_asn1_write_len(&a, attr[nattr].buf, (size_t)len);
        len += mbedtls_asn1_write_tag(&a, attr[nattr].buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        attr[nattr].len = (size_t)len;
        memmove(attr[nattr].buf, a, (size_t)len);
        nattr++;
    }
    /* pkiStatus "0" (SUCCESS) */
    {
        static const uint8_t v[] = {0x13, 0x01, '0'};
        uint8_t *a = attr[nattr].buf + sizeof(attr[nattr].buf); int len = 0;
        len += mbedtls_asn1_write_raw_buffer(&a, attr[nattr].buf, v, sizeof(v));
        len += mbedtls_asn1_write_len(&a, attr[nattr].buf, sizeof(v));
        len += mbedtls_asn1_write_tag(&a, attr[nattr].buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET);
        len += mbedtls_asn1_write_raw_buffer(&a, attr[nattr].buf, OID_PKI_STATUS, sizeof(OID_PKI_STATUS));
        len += mbedtls_asn1_write_len(&a, attr[nattr].buf, sizeof(OID_PKI_STATUS));
        len += mbedtls_asn1_write_tag(&a, attr[nattr].buf, MBEDTLS_ASN1_OID);
        len += mbedtls_asn1_write_len(&a, attr[nattr].buf, (size_t)len);
        len += mbedtls_asn1_write_tag(&a, attr[nattr].buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        attr[nattr].len = (size_t)len;
        memmove(attr[nattr].buf, a, (size_t)len);
        nattr++;
    }
    /* transactionID (PrintableString) -- optionally omitted (F3) */
    if (!def->omit_txid) {
        uint8_t v[2 + 64];
        v[0] = 0x13; v[1] = 64; memcpy(v + 2, TEST_TXID, 64);
        uint8_t *a = attr[nattr].buf + sizeof(attr[nattr].buf); int len = 0;
        len += mbedtls_asn1_write_raw_buffer(&a, attr[nattr].buf, v, sizeof(v));
        len += mbedtls_asn1_write_len(&a, attr[nattr].buf, sizeof(v));
        len += mbedtls_asn1_write_tag(&a, attr[nattr].buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET);
        len += mbedtls_asn1_write_raw_buffer(&a, attr[nattr].buf, OID_TXID, sizeof(OID_TXID));
        len += mbedtls_asn1_write_len(&a, attr[nattr].buf, sizeof(OID_TXID));
        len += mbedtls_asn1_write_tag(&a, attr[nattr].buf, MBEDTLS_ASN1_OID);
        len += mbedtls_asn1_write_len(&a, attr[nattr].buf, (size_t)len);
        len += mbedtls_asn1_write_tag(&a, attr[nattr].buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        attr[nattr].len = (size_t)len;
        memmove(attr[nattr].buf, a, (size_t)len);
        nattr++;
    }

    /* Sort attributes (X.690 §11.6 DER SET OF ordering) */
    for (int i = 0; i < nattr - 1; i++)
        for (int j = i + 1; j < nattr; j++) {
            size_t mn = attr[i].len < attr[j].len ? attr[i].len : attr[j].len;
            int c = memcmp(attr[i].buf, attr[j].buf, mn);
            if (c > 0 || (c == 0 && attr[i].len > attr[j].len)) {
                size_t tlen = attr[i].len; attr[i].len = attr[j].len; attr[j].len = tlen;
                uint8_t tb[128]; memcpy(tb, attr[i].buf, 128);
                memcpy(attr[i].buf, attr[j].buf, 128); memcpy(attr[j].buf, tb, 128);
            }
        }

    /* signedAttrs content (concatenated sorted attributes) */
    uint8_t sa_content[512]; size_t sa_content_len = 0;
    for (int i = 0; i < nattr; i++) {
        memcpy(sa_content + sa_content_len, attr[i].buf, attr[i].len);
        sa_content_len += attr[i].len;
    }

    /* SET-tagged signedAttrs to hash+sign (RFC 5652 §5.4). */
    uint8_t sa_set[600]; size_t pos = 0;
    sa_set[pos++] = 0x31;
    if (sa_content_len < 0x80) sa_set[pos++] = (uint8_t)sa_content_len;
    else { sa_set[pos++] = 0x81; sa_set[pos++] = (uint8_t)sa_content_len; }
    memcpy(sa_set + pos, sa_content, sa_content_len);
    size_t sa_set_len = pos + sa_content_len;

    uint8_t sa_hash[SHA256_LEN];
    if (mbedtls_sha256(sa_set, sa_set_len, sa_hash, 0) != 0) goto cleanup;

    uint8_t sig[512]; size_t sig_len = 0;
    {
        size_t slen = 0;
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
        int sr = mbedtls_pk_sign(&ra_key, MBEDTLS_MD_SHA256, sa_hash, SHA256_LEN,
                                 sig, sizeof(sig), &slen,
                                 mbedtls_ctr_drbg_random, &cr_ctr_drbg);
#else
        int sr = mbedtls_pk_sign(&ra_key, MBEDTLS_MD_SHA256, sa_hash, SHA256_LEN,
                                 sig, &slen,
                                 mbedtls_ctr_drbg_random, &cr_ctr_drbg);
#endif
        if (sr != 0) goto cleanup;
        sig_len = slen;
    }

    /* ---- Build outer SignedData ---------------------------------------- */
    uint8_t outer[12288];
    uint8_t *op = outer + sizeof(outer);
    size_t outer_total;
    {
        int len = 0;
        int si_len = 0;
        /* signature OCTET STRING */
        si_len += mbedtls_asn1_write_raw_buffer(&op, outer, sig, sig_len);
        si_len += mbedtls_asn1_write_len(&op, outer, sig_len);
        si_len += mbedtls_asn1_write_tag(&op, outer, MBEDTLS_ASN1_OCTET_STRING);
        /* signatureAlgorithm SEQUENCE { OID sha256WithRSA, NULL } */
        {
            int al = 0;
            al += mbedtls_asn1_write_null(&op, outer);
            al += mbedtls_asn1_write_raw_buffer(&op, outer, OID_SHA256_WITH_RSA, sizeof(OID_SHA256_WITH_RSA));
            al += mbedtls_asn1_write_len(&op, outer, sizeof(OID_SHA256_WITH_RSA));
            al += mbedtls_asn1_write_tag(&op, outer, MBEDTLS_ASN1_OID);
            al += mbedtls_asn1_write_len(&op, outer, (size_t)al);
            al += mbedtls_asn1_write_tag(&op, outer, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
            si_len += al;
        }
        /* signedAttrs [0] IMPLICIT (content = sa_content) -- F4 may retag */
        si_len += mbedtls_asn1_write_raw_buffer(&op, outer, sa_content, sa_content_len);
        si_len += mbedtls_asn1_write_len(&op, outer, sa_content_len);
        {
            uint8_t sa_tag = 0xA0;
            if (def->sa_tag_eoc) sa_tag = 0x00; /* F4: EOC instead of [0] */
            si_len += mbedtls_asn1_write_tag(&op, outer, sa_tag);
        }
        /* digestAlgorithm SEQUENCE { OID sha256, NULL } */
        {
            int al = 0;
            al += mbedtls_asn1_write_null(&op, outer);
            al += mbedtls_asn1_write_raw_buffer(&op, outer, OID_SHA256, sizeof(OID_SHA256));
            al += mbedtls_asn1_write_len(&op, outer, sizeof(OID_SHA256));
            al += mbedtls_asn1_write_tag(&op, outer, MBEDTLS_ASN1_OID);
            al += mbedtls_asn1_write_len(&op, outer, (size_t)al);
            al += mbedtls_asn1_write_tag(&op, outer, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
            si_len += al;
        }
        /* sid: issuerAndSerialNumber SEQUENCE { SEQUENCE{} (issuer), INTEGER 1 } */
        {
            int rl = 0;
            rl += mbedtls_asn1_write_int(&op, outer, 1);
            rl += wrap_tag(&op, outer, 0, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
            rl += mbedtls_asn1_write_len(&op, outer, (size_t)rl);
            rl += mbedtls_asn1_write_tag(&op, outer, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
            si_len += rl;
        }
        /* version INTEGER 1 */
        si_len += mbedtls_asn1_write_int(&op, outer, 1);
        /* SignerInfo SEQUENCE */
        si_len += mbedtls_asn1_write_len(&op, outer, (size_t)si_len);
        si_len += mbedtls_asn1_write_tag(&op, outer, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        /* signerInfos SET */
        {
            int sl = si_len;
            sl += mbedtls_asn1_write_len(&op, outer, (size_t)si_len);
            sl += mbedtls_asn1_write_tag(&op, outer, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET);
            len += sl;
        }
        /* certificates [0] IMPLICIT { RA cert } */
        {
            int cl = 0;
            cl += mbedtls_asn1_write_raw_buffer(&op, outer, ra_cert, ra_cert_len);
            cl += mbedtls_asn1_write_len(&op, outer, ra_cert_len);
            cl += mbedtls_asn1_write_tag(&op, outer, 0xA0);
            len += cl;
        }
        /* encapContentInfo SEQUENCE { OID data, [0] EXPLICIT { OCTET STRING env } } */
        {
            int el = 0;
            /* [0] { OCTET STRING (env_der) } */
            el += mbedtls_asn1_write_raw_buffer(&op, outer, env_der, env_total);
            el += mbedtls_asn1_write_len(&op, outer, env_total);
            el += mbedtls_asn1_write_tag(&op, outer, MBEDTLS_ASN1_OCTET_STRING);
            el += mbedtls_asn1_write_len(&op, outer, (size_t)el);
            el += mbedtls_asn1_write_tag(&op, outer, 0xA0);
            /* OID data */
            el += mbedtls_asn1_write_raw_buffer(&op, outer, OID_DATA, sizeof(OID_DATA));
            el += mbedtls_asn1_write_len(&op, outer, sizeof(OID_DATA));
            el += mbedtls_asn1_write_tag(&op, outer, MBEDTLS_ASN1_OID);
            el += mbedtls_asn1_write_len(&op, outer, (size_t)el);
            el += mbedtls_asn1_write_tag(&op, outer, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
            len += el;
        }
        /* digestAlgorithms SET { SEQUENCE { OID sha256, NULL } } */
        {
            int dl = 0;
            dl += mbedtls_asn1_write_null(&op, outer);
            dl += mbedtls_asn1_write_raw_buffer(&op, outer, OID_SHA256, sizeof(OID_SHA256));
            dl += mbedtls_asn1_write_len(&op, outer, sizeof(OID_SHA256));
            dl += mbedtls_asn1_write_tag(&op, outer, MBEDTLS_ASN1_OID);
            dl += mbedtls_asn1_write_len(&op, outer, (size_t)dl);
            dl += mbedtls_asn1_write_tag(&op, outer, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
            dl += mbedtls_asn1_write_len(&op, outer, (size_t)dl);
            dl += mbedtls_asn1_write_tag(&op, outer, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET);
            len += dl;
        }
        /* version INTEGER 3 */
        len += mbedtls_asn1_write_int(&op, outer, 3);
        /* SignedData SEQUENCE */
        len += mbedtls_asn1_write_len(&op, outer, (size_t)len);
        len += mbedtls_asn1_write_tag(&op, outer, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        /* [0] EXPLICIT */
        len += mbedtls_asn1_write_len(&op, outer, (size_t)len);
        len += mbedtls_asn1_write_tag(&op, outer, 0xA0);
        /* OID signedData */
        len += mbedtls_asn1_write_raw_buffer(&op, outer, OID_SIGNED_DATA, sizeof(OID_SIGNED_DATA));
        len += mbedtls_asn1_write_len(&op, outer, sizeof(OID_SIGNED_DATA));
        len += mbedtls_asn1_write_tag(&op, outer, MBEDTLS_ASN1_OID);
        /* ContentInfo SEQUENCE */
        len += mbedtls_asn1_write_len(&op, outer, (size_t)len);
        len += mbedtls_asn1_write_tag(&op, outer, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        outer_total = (size_t)len;
    }

    result = malloc(outer_total);
    if (!result) goto cleanup;
    memcpy(result, op, outer_total);
    *out = result;
    *out_len = outer_total;
    ret = 0;

cleanup:
    mbedtls_pk_free(&ra_key);
    if (ret != 0) mbedtls_pk_free(recip_key);
    return ret;
}

/* ========================================================================= */
/* Tests                                                                     */
/* ========================================================================= */

static int run_parse(const uint8_t *p7, size_t p7_len, mbedtls_pk_context *recip_key,
                     uint8_t *cert_buf, size_t *cert_len,
                     scep_pki_status_t *status, int *fail_info)
{
    *cert_len  = SCEP_MAX_CERT_DER;
    *status    = SCEP_PKI_STATUS_UNKNOWN;
    *fail_info = SCEP_FAIL_INFO_NONE;
    return scep_parse_certrep(p7, p7_len, TEST_TXID, recip_key,
                              mbedtls_ctr_drbg_random, &cr_ctr_drbg,
                              cert_buf, cert_len, status, fail_info);
}

/* No-regression: a valid SUCCESS CertRep parses and yields the issued cert. */
void test_valid_certrep_parses_and_recovers_cert(void)
{
    certrep_defects_t def = {0};
    uint8_t *p7 = NULL; size_t p7_len = 0;
    mbedtls_pk_context recip;
    int br = build_certrep(&def, &p7, &p7_len, &recip);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, br, "build_certrep (valid)");

    uint8_t cert_buf[SCEP_MAX_CERT_DER]; size_t cert_len;
    scep_pki_status_t status; int fail_info;
    int rc = run_parse(p7, p7_len, &recip, cert_buf, &cert_len, &status, &fail_info);

    TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "valid CertRep must parse OK");
    TEST_ASSERT_EQUAL_INT_MESSAGE(SCEP_PKI_STATUS_SUCCESS, status, "status SUCCESS");
    TEST_ASSERT_TRUE_MESSAGE(cert_len > 0, "issued cert recovered");
    /* recovered cert must parse as a real X.509 cert */
    mbedtls_x509_crt crt; mbedtls_x509_crt_init(&crt);
    int pr = mbedtls_x509_crt_parse_der(&crt, cert_buf, cert_len);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, pr, "recovered cert is valid DER");
    mbedtls_x509_crt_free(&crt);

    free(p7);
    mbedtls_pk_free(&recip);
}

/* F3: a CertRep with no transactionID signed attribute must be rejected. */
void test_certrep_missing_transaction_id_rejected(void)
{
    certrep_defects_t def = {0}; def.omit_txid = 1;
    uint8_t *p7 = NULL; size_t p7_len = 0;
    mbedtls_pk_context recip;
    int br = build_certrep(&def, &p7, &p7_len, &recip);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, br, "build_certrep (no txid)");

    uint8_t cert_buf[SCEP_MAX_CERT_DER]; size_t cert_len;
    scep_pki_status_t status; int fail_info;
    int rc = run_parse(p7, p7_len, &recip, cert_buf, &cert_len, &status, &fail_info);

    TEST_ASSERT_NOT_EQUAL_MESSAGE(0, rc,
        "CertRep missing transactionID must be rejected (RFC 8894)");

    free(p7);
    mbedtls_pk_free(&recip);
}

/* F2: encryptedContent whose length is not a multiple of 16 must be rejected. */
void test_certrep_unaligned_encrypted_content_rejected(void)
{
    certrep_defects_t def = {0}; def.unaligned_content = 1;
    uint8_t *p7 = NULL; size_t p7_len = 0;
    mbedtls_pk_context recip;
    int br = build_certrep(&def, &p7, &p7_len, &recip);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, br, "build_certrep (unaligned)");

    uint8_t cert_buf[SCEP_MAX_CERT_DER]; size_t cert_len;
    scep_pki_status_t status; int fail_info;
    int rc = run_parse(p7, p7_len, &recip, cert_buf, &cert_len, &status, &fail_info);

    TEST_ASSERT_NOT_EQUAL_MESSAGE(0, rc,
        "non-block-aligned encryptedContent must be rejected");

    free(p7);
    mbedtls_pk_free(&recip);
}

/* F5: EnvelopedData SEQUENCE replaced with EOC (0x00) must be rejected. */
void test_certrep_enveloped_data_eoc_tag_rejected(void)
{
    certrep_defects_t def = {0}; def.env_tag_eoc = 1;
    uint8_t *p7 = NULL; size_t p7_len = 0;
    mbedtls_pk_context recip;
    int br = build_certrep(&def, &p7, &p7_len, &recip);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, br, "build_certrep (env EOC)");

    uint8_t cert_buf[SCEP_MAX_CERT_DER]; size_t cert_len;
    scep_pki_status_t status; int fail_info;
    int rc = run_parse(p7, p7_len, &recip, cert_buf, &cert_len, &status, &fail_info);

    TEST_ASSERT_NOT_EQUAL_MESSAGE(0, rc,
        "EOC tag where EnvelopedData SEQUENCE expected must be rejected");

    free(p7);
    mbedtls_pk_free(&recip);
}

/* F4: signedAttrs [0] retagged as EOC (0x00) must be rejected (signature
 * recovery of signedAttrs fails / attr walk rejects EOC). */
void test_certrep_signed_attrs_eoc_tag_rejected(void)
{
    certrep_defects_t def = {0}; def.sa_tag_eoc = 1;
    uint8_t *p7 = NULL; size_t p7_len = 0;
    mbedtls_pk_context recip;
    int br = build_certrep(&def, &p7, &p7_len, &recip);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, br, "build_certrep (sa EOC)");

    uint8_t cert_buf[SCEP_MAX_CERT_DER]; size_t cert_len;
    scep_pki_status_t status; int fail_info;
    int rc = run_parse(p7, p7_len, &recip, cert_buf, &cert_len, &status, &fail_info);

    TEST_ASSERT_NOT_EQUAL_MESSAGE(0, rc,
        "EOC tag where signedAttrs [0] expected must be rejected");

    free(p7);
    mbedtls_pk_free(&recip);
}

/*
 * Registered from main() in test_scep_proto.c (this directory is one Unity
 * suite; main()/setUp()/tearDown() are defined there exactly once).
 */
void certrep_register_tests(void)
{
    RUN_TEST(test_valid_certrep_parses_and_recovers_cert);
    RUN_TEST(test_certrep_missing_transaction_id_rejected);
    RUN_TEST(test_certrep_unaligned_encrypted_content_rejected);
    RUN_TEST(test_certrep_enveloped_data_eoc_tag_rejected);
    RUN_TEST(test_certrep_signed_attrs_eoc_tag_rejected);
}
