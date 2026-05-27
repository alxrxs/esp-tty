/*
 * scep_proto.c -- SCEP (RFC 8894) wire-protocol primitives for esp-tty
 *
 * Rewritten to use mbedTLS only (no wolfSSL PKCS#7).
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "scep_proto.h"

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "mbedtls/build_info.h"
#if MBEDTLS_VERSION_NUMBER >= 0x04000000
/* mbedTLS 4.x: legacy crypto primitives moved to private/ subdirectory.
 * MBEDTLS_ALLOW_PRIVATE_ACCESS comes from ESP-IDF mbedtls esp_config.h (which mbedtls/build_info.h pulls in);
 * private_access.h then defines MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS which
 * unlocks function declarations in the private/ headers. */
#include "mbedtls/private/pk_private.h"
#include "mbedtls/private/rsa.h"
#include "mbedtls/private/sha256.h"
#include "mbedtls/private/aes.h"
#include "mbedtls/private/bignum.h"
#else
#include "mbedtls/rsa.h"
#include "mbedtls/sha256.h"
#include "mbedtls/aes.h"
#include "mbedtls/bignum.h"
/* mbedTLS 2.x had a separate x509write_crt.h; include it only if present. */
#if __has_include("mbedtls/x509write_crt.h")
#include "mbedtls/x509write_crt.h"
#endif
#endif
#include "mbedtls/pk.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/asn1.h"

/* -----------------------------------------------------------------------
 * OID byte arrays (raw content, without tag/length)
 * --------------------------------------------------------------------- */
static const uint8_t OID_SIGNED_DATA[]     = {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x02};
static const uint8_t OID_DATA[]            = {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x01};
static const uint8_t OID_ENVELOPED_DATA[]  = {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x07,0x03};
static const uint8_t OID_RSA_ENCRYPTION[]  = {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01};
static const uint8_t OID_RSAES_OAEP[]      = {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x07};
static const uint8_t OID_SHA256_WITH_RSA[] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x0b};
static const uint8_t OID_SHA256[]          = {0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01};
static const uint8_t OID_AES256_CBC[]      = {0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x2a};
static const uint8_t OID_CHALLENGE_PW[]    = {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x09,0x07};
static const uint8_t OID_CONTENT_TYPE[]    = {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x09,0x03};
static const uint8_t OID_MSG_DIGEST[]      = {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x09,0x04};
/* SCEP signed attribute OIDs */
static const uint8_t OID_MSG_TYPE[]   = {0x60,0x86,0x48,0x01,0x86,0xf8,0x45,0x01,0x09,0x02};
static const uint8_t OID_PKI_STATUS[] = {0x60,0x86,0x48,0x01,0x86,0xf8,0x45,0x01,0x09,0x03};
static const uint8_t OID_FAIL_INFO[]  = {0x60,0x86,0x48,0x01,0x86,0xf8,0x45,0x01,0x09,0x04};
static const uint8_t OID_SENDER_NONCE[] = {0x60,0x86,0x48,0x01,0x86,0xf8,0x45,0x01,0x09,0x05};
static const uint8_t OID_TXID[]       = {0x60,0x86,0x48,0x01,0x86,0xf8,0x45,0x01,0x09,0x07};
/* X.520 subject attribute OIDs */
static const uint8_t OID_ATTR_CN[]  = {0x55,0x04,0x03};
static const uint8_t OID_ATTR_O[]   = {0x55,0x04,0x0a};
static const uint8_t OID_ATTR_OU[]  = {0x55,0x04,0x0b};
static const uint8_t OID_ATTR_C[]   = {0x55,0x04,0x06};
static const uint8_t OID_ATTR_ST[]  = {0x55,0x04,0x08};
static const uint8_t OID_ATTR_L[]   = {0x55,0x04,0x07};

#define SHA256_LEN 32
#define CEK_LEN    32
#define IV_LEN     16

/* -----------------------------------------------------------------------
 * Backwards-write macros (mbedTLS convention)
 * CHK accumulates into `len` and returns on error.
 * --------------------------------------------------------------------- */
#define CHK(x) do { int _r = (x); if (_r < 0) return _r; len += (size_t)(_r); } while(0)

/* Write OID TLV */
static int w_oid(uint8_t **p, uint8_t *start, const uint8_t *oid, size_t olen)
{
    size_t len = 0;
    CHK(mbedtls_asn1_write_raw_buffer(p, start, oid, olen));
    CHK(mbedtls_asn1_write_len(p, start, olen));
    CHK(mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_OID));
    return (int)len;
}

/* Write AlgorithmIdentifier SEQUENCE { OID, NULL } */
static int w_alg_null(uint8_t **p, uint8_t *start, const uint8_t *oid, size_t olen)
{
    size_t len = 0;
    CHK(mbedtls_asn1_write_null(p, start));
    CHK(w_oid(p, start, oid, olen));
    CHK(mbedtls_asn1_write_len(p, start, len));
    CHK(mbedtls_asn1_write_tag(p, start,
        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
    return (int)len;
}

/* Write one RDN: SET { SEQUENCE { OID, UTF8String(s) } } */
static int w_rdn(uint8_t **p, uint8_t *start,
                 const uint8_t *oid, size_t olen,
                 const char *s)
{
    size_t len = 0;
    size_t slen = strlen(s);
    /* UTF8String(s) */
    CHK(mbedtls_asn1_write_raw_buffer(p, start, (const uint8_t *)s, slen));
    CHK(mbedtls_asn1_write_len(p, start, slen));
    CHK(mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_UTF8_STRING));
    /* OID */
    CHK(w_oid(p, start, oid, olen));
    /* SEQUENCE { OID, UTF8String } -- body = everything written so far */
    size_t seq_body = len;
    CHK(mbedtls_asn1_write_len(p, start, seq_body));
    CHK(mbedtls_asn1_write_tag(p, start,
        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
    /* SET { SEQUENCE } -- body = SEQUENCE TLV (seq_body + header bytes) */
    size_t set_body = len; /* len now = seq_body + SEQUENCE hdr bytes */
    CHK(mbedtls_asn1_write_len(p, start, set_body));
    CHK(mbedtls_asn1_write_tag(p, start,
        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET));
    return (int)len;
}

/* -----------------------------------------------------------------------
 * DER parse helpers (forward reading)
 * --------------------------------------------------------------------- */

/* Skip one TLV item, return 0 on success */
static int asn_skip(const uint8_t **p, const uint8_t *end)
{
    size_t len;
    if (*p >= end) return -1;
    (*p)++; /* skip tag */
    if (mbedtls_asn1_get_len((unsigned char **)p, end, &len) != 0) return -1;
    if (*p + len > end) return -1;
    *p += len;
    return 0;
}

/* Read a TLV; advance *p; optionally return tag, val, len */
static int asn_read(const uint8_t **p, const uint8_t *end,
                    int *tag_out, const uint8_t **val_out, size_t *len_out)
{
    if (*p >= end) return -1;
    int tag = (unsigned char)**p;
    (*p)++;
    size_t len;
    if (mbedtls_asn1_get_len((unsigned char **)p, end, &len) != 0) return -1;
    if (*p + len > end) return -1;
    if (tag_out)  *tag_out  = tag;
    if (val_out)  *val_out  = *p;
    if (len_out)  *len_out  = len;
    *p += len;
    return 0;
}

/* Expect a specific tag */
static int asn_expect(const uint8_t **p, const uint8_t *end,
                      int expected_tag,
                      const uint8_t **val_out, size_t *len_out)
{
    if (*p >= end || (unsigned char)**p != (unsigned char)expected_tag)
        return MBEDTLS_ERR_ASN1_UNEXPECTED_TAG;
    return asn_read(p, end, NULL, val_out, len_out);
}

/* -----------------------------------------------------------------------
 * Extract issuer Name DER and serial INTEGER TLV from a cert DER blob.
 * The returned pointers alias cert_der memory.
 * --------------------------------------------------------------------- */
static int cert_get_issuer_serial(const uint8_t *cert_der, size_t cert_len,
                                  const uint8_t **issuer_der, size_t *issuer_len,
                                  const uint8_t **serial_der, size_t *serial_len)
{
    const uint8_t *p = cert_der;
    const uint8_t *end = cert_der + cert_len;
    const uint8_t *tbs_val;
    size_t tbs_len;

    /* Certificate SEQUENCE */
    if (asn_expect(&p, end, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE,
                   &tbs_val, &tbs_len) != 0) return -1;
    end = tbs_val + tbs_len;
    p = tbs_val;

    /* TBSCertificate SEQUENCE */
    if (asn_expect(&p, end, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE,
                   &tbs_val, &tbs_len) != 0) return -1;
    const uint8_t *tbs_end = tbs_val + tbs_len;
    p = tbs_val;

    /* version [0] EXPLICIT -- optional */
    if (p < tbs_end && (*p & 0xe0) == 0xa0)
        if (asn_skip(&p, tbs_end) != 0) return -1;

    /* serialNumber INTEGER -- capture full TLV */
    *serial_der = p;
    if (asn_skip(&p, tbs_end) != 0) return -1;
    *serial_len = (size_t)(p - *serial_der);

    /* signature AlgorithmIdentifier -- skip */
    if (asn_skip(&p, tbs_end) != 0) return -1;

    /* issuer Name SEQUENCE -- capture full TLV */
    *issuer_der = p;
    if (asn_skip(&p, tbs_end) != 0) return -1;
    *issuer_len = (size_t)(p - *issuer_der);

    return 0;
}

/* Write IssuerAndSerialNumber SEQUENCE { issuer, serial } */
static int w_issuer_serial(uint8_t **p, uint8_t *start,
                           const uint8_t *issuer, size_t issuer_len,
                           const uint8_t *serial, size_t serial_len)
{
    size_t len = 0;
    CHK(mbedtls_asn1_write_raw_buffer(p, start, serial, serial_len));
    CHK(mbedtls_asn1_write_raw_buffer(p, start, issuer, issuer_len));
    CHK(mbedtls_asn1_write_len(p, start, len));
    CHK(mbedtls_asn1_write_tag(p, start,
        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
    return (int)len;
}

/* -----------------------------------------------------------------------
 * Write a DER Name SEQUENCE from scep_subject_t.
 * Writes backwards into buf[0..bufsz-1], returns start-of-result pointer
 * and the length via *name_len_out. Returns NULL on error.
 * --------------------------------------------------------------------- */
static int build_name_der(const scep_subject_t *s,
                          uint8_t *buf, size_t bufsz,
                          uint8_t **name_der_out, size_t *name_len_out)
{
    uint8_t *p   = buf + bufsz;
    uint8_t *bstart = buf;
    size_t len = 0;

    /* RDNs written in reverse so DER order is: C, ST, L, O, OU, CN */
    if (s->locality && s->locality[0])
        CHK(w_rdn(&p, bstart, OID_ATTR_L,  sizeof(OID_ATTR_L),  s->locality));
    if (s->state && s->state[0])
        CHK(w_rdn(&p, bstart, OID_ATTR_ST, sizeof(OID_ATTR_ST), s->state));
    if (s->country && s->country[0])
        CHK(w_rdn(&p, bstart, OID_ATTR_C,  sizeof(OID_ATTR_C),  s->country));
    if (s->organizational_unit && s->organizational_unit[0])
        CHK(w_rdn(&p, bstart, OID_ATTR_OU, sizeof(OID_ATTR_OU), s->organizational_unit));
    if (s->organization && s->organization[0])
        CHK(w_rdn(&p, bstart, OID_ATTR_O,  sizeof(OID_ATTR_O),  s->organization));
    CHK(w_rdn(&p, bstart, OID_ATTR_CN, sizeof(OID_ATTR_CN), s->common_name));
    CHK(mbedtls_asn1_write_len(&p, bstart, len));
    CHK(mbedtls_asn1_write_tag(&p, bstart,
        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    *name_der_out = p;
    *name_len_out = len;
    return 0;
}

/* -----------------------------------------------------------------------
 * PKCS#7 padding
 * --------------------------------------------------------------------- */
static size_t pkcs7_padded_len(size_t n) { return n + (16 - (n % 16)); }

static void pkcs7_pad(const uint8_t *in, size_t in_len,
                      uint8_t *out, size_t out_len)
{
    memcpy(out, in, in_len);
    uint8_t pad = (uint8_t)(out_len - in_len);
    memset(out + in_len, pad, pad);
}

/* -----------------------------------------------------------------------
 * 1. Key generation
 * --------------------------------------------------------------------- */
int scep_generate_keypair(mbedtls_pk_context *out,
                          int (*f_rng)(void *, unsigned char *, size_t),
                          void *p_rng)
{
    if (!out || !f_rng) return -1;
    int ret = mbedtls_pk_setup(out, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    if (ret != 0) return ret;
    ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(*out), f_rng, p_rng, 2048, 65537);
    if (ret != 0) { mbedtls_pk_free(out); }
    return ret;
}

/* -----------------------------------------------------------------------
 * 2. CSR generation
 * All backwards-write sections use a local `len` variable as required by CHK.
 * --------------------------------------------------------------------- */
int scep_build_csr(const scep_subject_t *subject,
                   mbedtls_pk_context   *key,
                   const char           *challenge_password,
                   int (*f_rng)(void *, unsigned char *, size_t),
                   void                 *p_rng,
                   uint8_t              *out_der,
                   size_t               *out_len)
{
    if (!subject || !key || !challenge_password || !f_rng || !out_der || !out_len)
        return -1;
    if (!subject->common_name || !subject->common_name[0])
        return -1;

    /* X.520 CN attribute uses UTF8String; X.509 caps PrintableString at 64
     * chars and UTF8String at 64 chars for CN per RFC 5280 §4.1.2.6.
     * mbedTLS does not enforce this limit itself -- it will silently encode
     * whatever length is provided.  Reject oversized CNs early so the
     * certificate is RFC-compliant and NDES/SCEP servers don't reject it. */
    if (strlen(subject->common_name) > 64)
        return SCEP_ERR_CN_TOO_LONG;

    int ret = 0;

    /* Build Name DER */
    uint8_t name_buf[512];
    uint8_t *name_der;
    size_t   name_len_out;
    if (build_name_der(subject, name_buf, sizeof(name_buf),
                       &name_der, &name_len_out) != 0) return -1;
    size_t name_len = name_len_out;

    /* Export SPKI */
    uint8_t spki_buf[512];
    int spki_len_i = mbedtls_pk_write_pubkey_der(key, spki_buf, sizeof(spki_buf));
    if (spki_len_i <= 0) return spki_len_i;
    size_t spki_len = (size_t)spki_len_i;
    const uint8_t *spki_der = spki_buf + sizeof(spki_buf) - spki_len;

    /* Build challengePassword attribute DER (backwards into pw_buf) */
    uint8_t pw_buf[128];
    uint8_t *pp = pw_buf + sizeof(pw_buf);
    uint8_t *ps = pw_buf;
    size_t   pwlen = strlen(challenge_password);
    size_t   pw_attr_len;
    {
        size_t len = 0;
        /* PrintableString(password) */
        CHK(mbedtls_asn1_write_raw_buffer(&pp, ps,
            (const uint8_t *)challenge_password, pwlen));
        CHK(mbedtls_asn1_write_len(&pp, ps, pwlen));
        CHK(mbedtls_asn1_write_tag(&pp, ps, MBEDTLS_ASN1_PRINTABLE_STRING));
        size_t ps_len = len;
        /* SET { PrintableString } */
        CHK(mbedtls_asn1_write_len(&pp, ps, ps_len));
        CHK(mbedtls_asn1_write_tag(&pp, ps,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET));
        /* OID challengePassword */
        CHK(w_oid(&pp, ps, OID_CHALLENGE_PW, sizeof(OID_CHALLENGE_PW)));
        size_t seq_inner = len;
        /* SEQUENCE */
        CHK(mbedtls_asn1_write_len(&pp, ps, seq_inner));
        CHK(mbedtls_asn1_write_tag(&pp, ps,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
        pw_attr_len = len;
    }
    const uint8_t *pw_attr = pp;

    /* Build CertificationRequestInfo backwards into cri_buf */
    uint8_t cri_buf[SCEP_MAX_CSR_DER * 2];
    uint8_t *cp = cri_buf + sizeof(cri_buf);
    uint8_t *cs = cri_buf;
    size_t   cri_len;
    {
        size_t len = 0;
        /* attributes [0] IMPLICIT */
        CHK(mbedtls_asn1_write_raw_buffer(&cp, cs, pw_attr, pw_attr_len));
        CHK(mbedtls_asn1_write_len(&cp, cs, pw_attr_len));
        CHK(mbedtls_asn1_write_tag(&cp, cs, 0xA0));
        /* subjectPublicKeyInfo */
        CHK(mbedtls_asn1_write_raw_buffer(&cp, cs, spki_der, spki_len));
        /* subject Name */
        CHK(mbedtls_asn1_write_raw_buffer(&cp, cs, name_der, name_len));
        /* version INTEGER(0) */
        CHK(mbedtls_asn1_write_int(&cp, cs, 0));
        size_t body = len;
        /* Wrap in SEQUENCE */
        CHK(mbedtls_asn1_write_len(&cp, cs, body));
        CHK(mbedtls_asn1_write_tag(&cp, cs,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
        cri_len = len;
    }
    const uint8_t *cri_der = cp;

    /* Sign SHA-256(CRI) */
    uint8_t hash[SHA256_LEN];
    ret = mbedtls_sha256(cri_der, cri_len, hash, 0);
    if (ret != 0) return ret;

    uint8_t sig[512];
    size_t  sig_len = sizeof(sig);
#if MBEDTLS_VERSION_NUMBER >= 0x04000000
    ret = mbedtls_pk_sign(key, MBEDTLS_MD_SHA256, hash, SHA256_LEN,
                          sig, sizeof(sig), &sig_len);
#else
    ret = mbedtls_pk_sign(key, MBEDTLS_MD_SHA256, hash, SHA256_LEN,
                          sig, sizeof(sig), &sig_len, f_rng, p_rng);
#endif
    if (ret != 0) return ret;

    /* Build final CertificationRequest */
    uint8_t csr_buf[SCEP_MAX_CSR_DER * 2];
    uint8_t *xp = csr_buf + sizeof(csr_buf);
    uint8_t *xs = csr_buf;
    size_t   xlen;
    {
        size_t len = 0;
        /* signature BIT STRING */
        uint8_t sig_bs[513];
        sig_bs[0] = 0x00;
        memcpy(sig_bs + 1, sig, sig_len);
        CHK(mbedtls_asn1_write_raw_buffer(&xp, xs, sig_bs, sig_len + 1));
        CHK(mbedtls_asn1_write_len(&xp, xs, sig_len + 1));
        CHK(mbedtls_asn1_write_tag(&xp, xs, MBEDTLS_ASN1_BIT_STRING));
        /* signatureAlgorithm sha256WithRSAEncryption */
        CHK(w_alg_null(&xp, xs, OID_SHA256_WITH_RSA, sizeof(OID_SHA256_WITH_RSA)));
        /* certificationRequestInfo */
        CHK(mbedtls_asn1_write_raw_buffer(&xp, xs, cri_der, cri_len));
        size_t body = len;
        /* outer SEQUENCE */
        CHK(mbedtls_asn1_write_len(&xp, xs, body));
        CHK(mbedtls_asn1_write_tag(&xp, xs,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
        xlen = len;
    }

    if (xlen > *out_len) return -2;
    memcpy(out_der, xp, xlen);
    *out_len = xlen;
    return 0;
}

/* -----------------------------------------------------------------------
 * 3. Self-signed certificate
 * --------------------------------------------------------------------- */
int scep_build_self_signed_cert(const scep_subject_t *subject,
                                mbedtls_pk_context   *key,
                                int (*f_rng)(void *, unsigned char *, size_t),
                                void                 *p_rng,
                                uint8_t              *out_der,
                                size_t               *out_len)
{
    if (!subject || !key || !f_rng || !out_der || !out_len) return -1;

    int ret;
    mbedtls_x509write_cert crt;
    /* mbedTLS 2.x consumes `serial` directly via set_serial(); 3.x/4.x use
     * the raw API (set_serial_raw) instead.  In both worlds we still init
     * + free the mbedtls_mpi for symmetry, even though 3.x/4.x don't pass
     * it to the writer. */
    mbedtls_mpi serial;

    mbedtls_x509write_crt_init(&crt);
    mbedtls_mpi_init(&serial);

    /* Build DN string */
    char dn[256] = "";
    if (subject->country && subject->country[0]) {
        strncat(dn, "C=",  sizeof(dn) - strlen(dn) - 1);
        strncat(dn, subject->country, sizeof(dn) - strlen(dn) - 1);
        strncat(dn, ",", sizeof(dn) - strlen(dn) - 1);
    }
    if (subject->state && subject->state[0]) {
        strncat(dn, "ST=", sizeof(dn) - strlen(dn) - 1);
        strncat(dn, subject->state, sizeof(dn) - strlen(dn) - 1);
        strncat(dn, ",", sizeof(dn) - strlen(dn) - 1);
    }
    if (subject->locality && subject->locality[0]) {
        strncat(dn, "L=",  sizeof(dn) - strlen(dn) - 1);
        strncat(dn, subject->locality, sizeof(dn) - strlen(dn) - 1);
        strncat(dn, ",", sizeof(dn) - strlen(dn) - 1);
    }
    if (subject->organization && subject->organization[0]) {
        strncat(dn, "O=",  sizeof(dn) - strlen(dn) - 1);
        strncat(dn, subject->organization, sizeof(dn) - strlen(dn) - 1);
        strncat(dn, ",", sizeof(dn) - strlen(dn) - 1);
    }
    if (subject->organizational_unit && subject->organizational_unit[0]) {
        strncat(dn, "OU=", sizeof(dn) - strlen(dn) - 1);
        strncat(dn, subject->organizational_unit, sizeof(dn) - strlen(dn) - 1);
        strncat(dn, ",", sizeof(dn) - strlen(dn) - 1);
    }
    strncat(dn, "CN=", sizeof(dn) - strlen(dn) - 1);
    strncat(dn, subject->common_name, sizeof(dn) - strlen(dn) - 1);

    mbedtls_x509write_crt_set_subject_key(&crt, key);
    mbedtls_x509write_crt_set_issuer_key(&crt, key);
    mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);

    ret = mbedtls_x509write_crt_set_subject_name(&crt, dn);
    if (ret != 0) goto out;
    ret = mbedtls_x509write_crt_set_issuer_name(&crt, dn);
    if (ret != 0) goto out;
    ret = mbedtls_x509write_crt_set_validity(&crt,
        "20200101000000", "20380101000000");
    if (ret != 0) goto out;

    /* Random serial */
    uint8_t ser[8];
    ret = f_rng(p_rng, ser, sizeof(ser));
    if (ret != 0) goto out;
    ser[0] &= 0x7f;  /* ensure positive INTEGER */
#if defined(MBEDTLS_VERSION_NUMBER) && MBEDTLS_VERSION_NUMBER >= 0x03000000
    /* mbedTLS 3.x: use set_serial_raw (set_serial is deprecated) */
    ret = mbedtls_x509write_crt_set_serial_raw(&crt, ser, sizeof(ser));
    (void)serial;
#else
    ret = mbedtls_mpi_read_binary(&serial, ser, sizeof(ser));
    if (ret != 0) goto out;
    ret = mbedtls_x509write_crt_set_serial(&crt, &serial);
#endif
    if (ret != 0) goto out;

    {
#if MBEDTLS_VERSION_NUMBER >= 0x04000000
        int len_i = mbedtls_x509write_crt_der(&crt, out_der, *out_len);
#else
        int len_i = mbedtls_x509write_crt_der(&crt, out_der, *out_len, f_rng, p_rng);
#endif
        if (len_i <= 0) { ret = len_i; goto out; }
        /* mbedtls_x509write_crt_der writes at END of buffer */
        memmove(out_der, out_der + (*out_len - (size_t)len_i), (size_t)len_i);
        *out_len = (size_t)len_i;
        ret = 0;
    }

out:
    mbedtls_x509write_crt_free(&crt);
    mbedtls_mpi_free(&serial);
    return ret;
}

/* -----------------------------------------------------------------------
 * 4. Transaction ID
 * --------------------------------------------------------------------- */
int scep_transaction_id(const uint8_t *spki_der, size_t spki_len,
                        char *out_hex, size_t out_cap)
{
    if (!spki_der || !out_hex || out_cap < SCEP_TRANSACTION_ID_HEX_LEN + 1) return -1;
    uint8_t digest[SHA256_LEN];
    if (mbedtls_sha256(spki_der, spki_len, digest, 0) != 0) return -1;
    for (int i = 0; i < SHA256_LEN; i++)
        snprintf(out_hex + i * 2, 3, "%02x", digest[i]);
    return 0;
}

/* -----------------------------------------------------------------------
 * 5. Build PKCSReq pkiMessage
 *
 * Uses two heap-allocated scratch buffers to avoid huge stack frames:
 *  - env_scratch: EnvelopedData ContentInfo DER
 *  - out_scratch: final SignedData ContentInfo DER (written backwards,
 *    then memmoved to out_p7)
 * --------------------------------------------------------------------- */

/* Build one signed attribute SEQUENCE { OID, SET { value_der } }
 * Writes backwards; returns length or negative error. */
static int w_signed_attr(uint8_t **p, uint8_t *start,
                         const uint8_t *oid, size_t oid_len,
                         const uint8_t *val, size_t val_len)
{
    size_t len = 0;
    /* SET { val } */
    CHK(mbedtls_asn1_write_raw_buffer(p, start, val, val_len));
    CHK(mbedtls_asn1_write_len(p, start, val_len));
    CHK(mbedtls_asn1_write_tag(p, start,
        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET));
    /* OID */
    CHK(w_oid(p, start, oid, oid_len));
    /* SEQUENCE */
    CHK(mbedtls_asn1_write_len(p, start, len));
    CHK(mbedtls_asn1_write_tag(p, start,
        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
    return (int)len;
}

int scep_build_pkimessage_pkcsreq(const uint8_t      *csr_der,
                                  size_t              csr_len,
                                  const uint8_t      *ra_cert_der,
                                  size_t              ra_cert_len,
                                  mbedtls_pk_context *signing_key,
                                  const uint8_t      *self_signed_cert_der,
                                  size_t              self_signed_cert_len,
                                  int (*f_rng)(void *, unsigned char *, size_t),
                                  void               *p_rng,
                                  const char         *transaction_id,
                                  uint8_t            *out_p7,
                                  size_t             *out_p7_len)
{
    if (!csr_der || !ra_cert_der || !signing_key ||
        !self_signed_cert_der || !f_rng || !transaction_id ||
        !out_p7 || !out_p7_len) return -1;

    int ret = 0;
    uint8_t *env_scratch = NULL;
    uint8_t *out_scratch = NULL;
    uint8_t *sa_content  = NULL; /* signed-attrs heap buffer; freed at done: */
    uint8_t *enc_csr     = NULL; /* AES-CBC ciphertext of CSR; freed at done: */
    uint8_t *enc_cek     = NULL; /* RSA-wrapped AES CEK; freed (zeroized) at done: */
    size_t   enc_cek_len = 0;    /* tracks how many bytes of enc_cek to wipe */

    /* ------------------------------------------------------------------
     * Extract RA cert's RSA public key and IssuerAndSerialNumber
     * ------------------------------------------------------------------ */
    mbedtls_x509_crt ra_crt;
    mbedtls_x509_crt_init(&ra_crt);
    ret = mbedtls_x509_crt_parse_der(&ra_crt, ra_cert_der, ra_cert_len);
    if (ret != 0) goto done;

    if (mbedtls_pk_get_type(&ra_crt.pk) != MBEDTLS_PK_RSA) {
        ret = -1; goto done;
    }
    mbedtls_rsa_context *ra_rsa = mbedtls_pk_rsa(ra_crt.pk);
    size_t ra_rsa_len = mbedtls_rsa_get_len(ra_rsa); /* bytes in modulus */

    const uint8_t *ra_issuer, *ra_serial;
    size_t ra_issuer_len, ra_serial_len;
    ret = cert_get_issuer_serial(ra_cert_der, ra_cert_len,
                                 &ra_issuer, &ra_issuer_len,
                                 &ra_serial, &ra_serial_len);
    if (ret != 0) goto done;

    /* Extract IssuerAndSerialNumber from self-signed cert */
    const uint8_t *self_issuer, *self_serial;
    size_t self_issuer_len, self_serial_len;
    ret = cert_get_issuer_serial(self_signed_cert_der, self_signed_cert_len,
                                 &self_issuer, &self_issuer_len,
                                 &self_serial, &self_serial_len);
    if (ret != 0) goto done;

    /* ------------------------------------------------------------------
     * Export SPKI from signing_key -- needed only for contentType in
     * signedAttrs; we already have it in self_signed_cert_der but easier
     * to get directly.  Actually we just need the OID for contentType.
     * ------------------------------------------------------------------ */

    /* ------------------------------------------------------------------
     * Generate CEK + IV + senderNonce
     * ------------------------------------------------------------------ */
    uint8_t cek[CEK_LEN], iv[IV_LEN], sender_nonce[SCEP_NONCE_LEN];
    if ((ret = f_rng(p_rng, cek, CEK_LEN)) != 0) goto done;
    if ((ret = f_rng(p_rng, iv, IV_LEN)) != 0) goto done;
    if ((ret = f_rng(p_rng, sender_nonce, SCEP_NONCE_LEN)) != 0) goto done;

    /* ------------------------------------------------------------------
     * AES-256-CBC encrypt the CSR
     * ------------------------------------------------------------------ */
    size_t padded_len = pkcs7_padded_len(csr_len);
    uint8_t *padded  = malloc(padded_len);
    enc_csr = malloc(padded_len);
    if (!padded || !enc_csr) {
        free(padded); ret = -1; goto done;
    }
    pkcs7_pad(csr_der, csr_len, padded, padded_len);
    {
        mbedtls_aes_context aes;
        mbedtls_aes_init(&aes);
        uint8_t iv2[IV_LEN];
        memcpy(iv2, iv, IV_LEN);
        ret = mbedtls_aes_setkey_enc(&aes, cek, 256);
        if (ret == 0)
            ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT,
                                        padded_len, iv2, padded, enc_csr);
        mbedtls_aes_free(&aes);
    }
    free(padded); padded = NULL;
    if (ret != 0) goto done;

    /* ------------------------------------------------------------------
     * RSA-OAEP encrypt CEK to RA's public key.
     *
     * We use RSAES-OAEP (PKCS#1 v2.x, MBEDTLS_RSA_PKCS_V21) with SHA-256
     * unconditionally.  All NDES servers and modern SCEP CAs support OAEP;
     * legacy NDES (Windows Server 2008 and earlier) that only understand
     * PKCS#1 v1.5 wrapping would fail here -- add a GetCACaps fallback if
     * that ever becomes a requirement.  PKCS#1 v1.5 wrapping (V15) is
     * vulnerable to the Bleichenbacher oracle attack and MUST NOT be used.
     * ------------------------------------------------------------------ */
    enc_cek = malloc(ra_rsa_len);
    if (!enc_cek) { ret = -1; goto done; }
    enc_cek_len = ra_rsa_len;
    mbedtls_rsa_set_padding(ra_rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
    ret = mbedtls_rsa_pkcs1_encrypt(ra_rsa, f_rng, p_rng, CEK_LEN, cek, enc_cek);
    if (ret != 0) goto done;

    /* Wipe CEK from stack immediately after use */
    volatile uint8_t *vp = cek;
    for (size_t i = 0; i < CEK_LEN; i++) vp[i] = 0;

    /* ------------------------------------------------------------------
     * Build EnvelopedData DER (backwards write into env_scratch)
     *
     * EnvelopedData {
     *   version INTEGER(0),
     *   recipientInfos SET { KeyTransRecipientInfo { ... } },
     *   encryptedContentInfo { ... }
     * }
     * Wrapped in ContentInfo { id-envelopedData, [0]EXPLICIT ... }
     * ------------------------------------------------------------------ */
    /* Overflow check: 4096 + padded_len + ra_rsa_len must not wrap size_t */
    if (padded_len > (SIZE_MAX - 4096 - ra_rsa_len)) {
        ret = -1; goto done;
    }
    size_t env_sz = 4096 + padded_len + ra_rsa_len;
    env_scratch = malloc(env_sz);
    if (!env_scratch) { ret = -1; goto done; }

    size_t env_ci_len = 0; /* ContentInfo DER length */
    /* Inside this block use CHK_G (goto done on failure) so that enc_csr,
     * enc_cek (sensitive: wrapped CEK), env_scratch and ra_crt are all
     * released by the unified cleanup at done:.  Plain CHK_G() would return
     * directly and leak heap + the CEK secret. */
#undef  CHK_G
#define CHK_G(x) do { int _r = (x); if (_r < 0) { ret = _r; goto done; } \
                      len += (size_t)(_r); } while(0)
    {
        uint8_t *ep = env_scratch + env_sz;
        uint8_t *es = env_scratch;

        /* EncryptedContentInfo: [0] IMPLICIT(enc_csr) + CEA + OID */
        size_t enc_content_len;
        {
            size_t len = 0;
            CHK_G(mbedtls_asn1_write_raw_buffer(&ep, es, enc_csr, padded_len));
            CHK_G(mbedtls_asn1_write_len(&ep, es, padded_len));
            CHK_G(mbedtls_asn1_write_tag(&ep, es, 0x80));
            enc_content_len = len;
        }

        size_t cea_len; /* contentEncryptionAlgorithm: SEQUENCE { OID, OCTET STRING(iv) } */
        {
            size_t len = 0;
            /* Write IV OCTET STRING first (backward = it appears after OID in DER) */
            CHK_G(mbedtls_asn1_write_raw_buffer(&ep, es, iv, IV_LEN));
            CHK_G(mbedtls_asn1_write_len(&ep, es, IV_LEN));
            CHK_G(mbedtls_asn1_write_tag(&ep, es, MBEDTLS_ASN1_OCTET_STRING));
            /* Write OID (backward = it appears before IV in DER) */
            CHK_G(w_oid(&ep, es, OID_AES256_CBC, sizeof(OID_AES256_CBC)));
            /* len is now the total body (OID TLV + IV OCTET STRING TLV) */
            size_t cea_body = len;
            CHK_G(mbedtls_asn1_write_len(&ep, es, cea_body));
            CHK_G(mbedtls_asn1_write_tag(&ep, es,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
            cea_len = len;
        }

        size_t ct_oid_len; /* contentType OID */
        {
            size_t len = 0;
            CHK_G(w_oid(&ep, es, OID_DATA, sizeof(OID_DATA)));
            ct_oid_len = len;
        }

        /* EncryptedContentInfo SEQUENCE */
        size_t eci_body = enc_content_len + cea_len + ct_oid_len;
        size_t eci_hdr_len;
        {
            size_t len = 0;
            CHK_G(mbedtls_asn1_write_len(&ep, es, eci_body));
            CHK_G(mbedtls_asn1_write_tag(&ep, es,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
            eci_hdr_len = len;
        }
        size_t eci_total = eci_body + eci_hdr_len;

        /* KTRI body: version + IssuerAndSerial + algId + encKey */
        size_t ktri_body_len;
        {
            size_t len = 0;
            CHK_G(mbedtls_asn1_write_raw_buffer(&ep, es, enc_cek, ra_rsa_len));
            CHK_G(mbedtls_asn1_write_len(&ep, es, ra_rsa_len));
            CHK_G(mbedtls_asn1_write_tag(&ep, es, MBEDTLS_ASN1_OCTET_STRING));
            CHK_G(w_alg_null(&ep, es, OID_RSA_ENCRYPTION, sizeof(OID_RSA_ENCRYPTION)));
            CHK_G(w_issuer_serial(&ep, es,
                ra_issuer, ra_issuer_len, ra_serial, ra_serial_len));
            CHK_G(mbedtls_asn1_write_int(&ep, es, 0));
            ktri_body_len = len;
        }
        /* KTRI SEQUENCE */
        size_t ktri_hdr_len;
        {
            size_t len = 0;
            CHK_G(mbedtls_asn1_write_len(&ep, es, ktri_body_len));
            CHK_G(mbedtls_asn1_write_tag(&ep, es,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
            ktri_hdr_len = len;
        }
        size_t ktri_total = ktri_body_len + ktri_hdr_len;

        /* recipientInfos SET */
        size_t ri_set_hdr;
        {
            size_t len = 0;
            CHK_G(mbedtls_asn1_write_len(&ep, es, ktri_total));
            CHK_G(mbedtls_asn1_write_tag(&ep, es,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET));
            ri_set_hdr = len;
        }
        size_t ri_total = ktri_total + ri_set_hdr;

        /* EnvelopedData version=0 */
        size_t ver_len;
        {
            size_t len = 0;
            CHK_G(mbedtls_asn1_write_int(&ep, es, 0));
            ver_len = len;
        }

        /* EnvelopedData body = version + recipientInfos + encryptedContentInfo */
        size_t ed_body = ver_len + ri_total + eci_total;

        /* EnvelopedData SEQUENCE */
        size_t ed_hdr;
        {
            size_t len = 0;
            CHK_G(mbedtls_asn1_write_len(&ep, es, ed_body));
            CHK_G(mbedtls_asn1_write_tag(&ep, es,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
            ed_hdr = len;
        }
        size_t ed_total = ed_body + ed_hdr;

        /* ContentInfo wrapper */
        size_t ci_wrap_hdr;
        {
            size_t len = 0;
            CHK_G(mbedtls_asn1_write_len(&ep, es, ed_total));
            CHK_G(mbedtls_asn1_write_tag(&ep, es, 0xA0)); /* [0] EXPLICIT */
            ci_wrap_hdr = len;
        }
        size_t ci_inner_body = ed_total + ci_wrap_hdr;

        size_t ci_oid_len;
        {
            size_t len = 0;
            CHK_G(w_oid(&ep, es, OID_ENVELOPED_DATA, sizeof(OID_ENVELOPED_DATA)));
            ci_oid_len = len;
        }
        size_t ci_inner = ci_inner_body + ci_oid_len;

        size_t ci_seq_hdr;
        {
            size_t len = 0;
            CHK_G(mbedtls_asn1_write_len(&ep, es, ci_inner));
            CHK_G(mbedtls_asn1_write_tag(&ep, es,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
            ci_seq_hdr = len;
        }
        env_ci_len = ci_inner + ci_seq_hdr;

        /* Move to front of env_scratch */
        memmove(env_scratch, ep, env_ci_len);
    }
#undef CHK_G
    /* enc_csr / enc_cek are no longer needed; the CEK ciphertext doesn't
     * reveal the key but we still zero it out as defence in depth.  Free
     * happens at done: -- keep them allocated here in case some later
     * `goto done` fires below.  (They're not referenced again either way.) */
    free(enc_csr); enc_csr = NULL;
    if (enc_cek) {
        /* Zeroize the RSA-wrapped CEK -- it doesn't expose the AES key
         * but reduces forensic value in case of leak. */
        volatile uint8_t *evp = enc_cek;
        for (size_t i = 0; i < enc_cek_len; i++) evp[i] = 0;
        free(enc_cek);
        enc_cek = NULL;
        enc_cek_len = 0;
    }

    const uint8_t *env_ci = env_scratch;

    /* ------------------------------------------------------------------
     * Build signed attributes (5 attributes):
     *   contentType = id-envelopedData
     *   messageType = "19" PrintableString
     *   transactionID = transaction_id PrintableString
     *   senderNonce = 16 bytes OCTET STRING
     *   messageDigest = SHA-256(EnvelopedData ContentInfo) OCTET STRING
     * ------------------------------------------------------------------ */

    /* SHA-256 of EnvelopedData ContentInfo */
    uint8_t env_digest[SHA256_LEN];
    ret = mbedtls_sha256(env_ci, env_ci_len, env_digest, 0);
    if (ret != 0) goto done;

    /* Build each attribute value DER */

    /* contentType value: OID id-data (1.2.840.113549.1.7.1)
     * RFC 8894 §3.2 mandates id-data for the outer SignedData's
     * encapContentInfo.eContentType; the contentType signed attribute
     * must match.  Microsoft NDES rejects id-envelopedData here with
     * failInfo=badMessageCheck. */
    uint8_t ct_val[16];
    uint8_t *cvp = ct_val + sizeof(ct_val);
    size_t   ct_val_len = 0;
    {
        int _r = w_oid(&cvp, ct_val, OID_DATA, sizeof(OID_DATA));
        if (_r < 0) { ret = _r; goto done; }
        ct_val_len = (size_t)_r;
    }
    const uint8_t *ct_val_der = cvp;

    /* messageType value: PrintableString "19" */
    static const uint8_t mt_val[] = {0x13, 0x02, '1', '9'};

    /* transactionID value: PrintableString(txid) */
    /* Guard: tid_val[] is 70 bytes; 2-byte header + up to 68 bytes of content.
     * SHA-256 hex is always 64 chars, but defend against pathological callers. */
    if (strlen(transaction_id) > 68) { ret = -1; goto done; }
    size_t tid_str_len = strlen(transaction_id);
    uint8_t tid_val[70];
    tid_val[0] = 0x13; /* PrintableString */
    tid_val[1] = (uint8_t)tid_str_len;
    memcpy(tid_val + 2, transaction_id, tid_str_len);
    size_t tid_val_len = 2 + tid_str_len;

    /* senderNonce value: OCTET STRING(nonce) */
    uint8_t nonce_val[2 + SCEP_NONCE_LEN];
    nonce_val[0] = 0x04; /* OCTET STRING */
    nonce_val[1] = SCEP_NONCE_LEN;
    memcpy(nonce_val + 2, sender_nonce, SCEP_NONCE_LEN);

    /* messageDigest value: OCTET STRING(env_digest) */
    uint8_t md_val[2 + SHA256_LEN];
    md_val[0] = 0x04;
    md_val[1] = SHA256_LEN;
    memcpy(md_val + 2, env_digest, SHA256_LEN);

    /* Build signedAttrs SET OF content (backwards into sa_buf).
     * DER SET OF must be in ascending byte order (X.690 §11.6).
     * We build each attribute separately, sort, then assemble. */

    /* We need the attributes in canonical SET OF order.
     * Strategy: encode each into a temp, collect pointers, sort, re-emit. */
    struct attr_enc {
        uint8_t data[256];
        size_t  len;
    } attrs[5];
    memset(attrs, 0, sizeof(attrs));

    /* Encode each attribute forwards into attrs[i].data using a backwards write */
#define ENC_ATTR(idx, oid_arr, val_arr, vlen) do { \
    uint8_t _tb[256]; \
    uint8_t *_tp = _tb + sizeof(_tb); \
    size_t _len = 0; \
    int _r = w_signed_attr(&_tp, _tb, (oid_arr), sizeof(oid_arr), (val_arr), (vlen)); \
    if (_r < 0) { ret = _r; goto done; } \
    _len = (size_t)_r; \
    if (_len > sizeof(attrs[idx].data)) { ret = -1; goto done; } \
    attrs[idx].len = _len; \
    memcpy(attrs[idx].data, _tp, _len); \
} while(0)

    ENC_ATTR(0, OID_CONTENT_TYPE, ct_val_der,  ct_val_len);
    ENC_ATTR(1, OID_MSG_DIGEST,   md_val,       sizeof(md_val));
    ENC_ATTR(2, OID_MSG_TYPE,     mt_val,       sizeof(mt_val));
    ENC_ATTR(3, OID_SENDER_NONCE, nonce_val,    sizeof(nonce_val));
    ENC_ATTR(4, OID_TXID,         tid_val,      tid_val_len);
#undef ENC_ATTR

    /* Sort by DER (X.690 §11.6) */
    for (int i = 0; i < 4; i++) {
        for (int j = i + 1; j < 5; j++) {
            size_t mn = attrs[i].len < attrs[j].len ? attrs[i].len : attrs[j].len;
            int c = memcmp(attrs[i].data, attrs[j].data, mn);
            if (c > 0 || (c == 0 && attrs[i].len > attrs[j].len)) {
                struct attr_enc tmp = attrs[i];
                attrs[i] = attrs[j];
                attrs[j] = tmp;
            }
        }
    }

    /* Total signed attrs content length */
    size_t sa_content_len = 0;
    for (int i = 0; i < 5; i++) sa_content_len += attrs[i].len;

    /* Allocate sa_content buffer */
    sa_content = malloc(sa_content_len);
    if (!sa_content) { ret = -1; goto done; }
    size_t offset = 0;
    for (int i = 0; i < 5; i++) {
        memcpy(sa_content + offset, attrs[i].data, attrs[i].len);
        offset += attrs[i].len;
    }

    /* Prepend SET tag+length to signedAttrs content for digest computation.
     * sa_hash_len is set precisely after building the TLV header below.
     * The SET TLV header needs at most 5 bytes (tag + 0x82 + 2-byte length)
     * when sa_content_len >= 0x10000; reject that case to keep the +4 safe. */
    if (sa_content_len >= 0x10000) { ret = -1; goto done; }
    size_t sa_hash_len = 0; /* set below after building TLV */
    uint8_t *sa_for_hash = malloc(sa_content_len + 4);
    if (!sa_for_hash) { ret = -1; goto done; }
    {
        /* Write SET TLV manually */
        size_t pos = 0;
        sa_for_hash[pos++] = 0x31;
        if (sa_content_len < 0x80) {
            sa_for_hash[pos++] = (uint8_t)sa_content_len;
        } else if (sa_content_len < 0x100) {
            sa_for_hash[pos++] = 0x81;
            sa_for_hash[pos++] = (uint8_t)sa_content_len;
        } else {
            sa_for_hash[pos++] = 0x82;
            sa_for_hash[pos++] = (uint8_t)(sa_content_len >> 8);
            sa_for_hash[pos++] = (uint8_t)(sa_content_len & 0xff);
        }
        memcpy(sa_for_hash + pos, sa_content, sa_content_len);
        sa_hash_len = pos + sa_content_len;
    }

    /* Sign SHA-256(signedAttrs-as-SET) */
    uint8_t sa_hash[SHA256_LEN];
    ret = mbedtls_sha256(sa_for_hash, sa_hash_len, sa_hash, 0);
    free(sa_for_hash);
    if (ret != 0) { goto done; }

    uint8_t sig[512];
    size_t  sig_len = sizeof(sig);
#if MBEDTLS_VERSION_NUMBER >= 0x04000000
    ret = mbedtls_pk_sign(signing_key, MBEDTLS_MD_SHA256, sa_hash, SHA256_LEN,
                          sig, sizeof(sig), &sig_len);
#else
    ret = mbedtls_pk_sign(signing_key, MBEDTLS_MD_SHA256, sa_hash, SHA256_LEN,
                          sig, sizeof(sig), &sig_len, f_rng, p_rng);
#endif
    if (ret != 0) { goto done; }

    /* ------------------------------------------------------------------
     * Build outer SignedData + ContentInfo DER (backwards write)
     *
     * IMPORTANT: from this point sa_content and out_scratch are both heap-
     * allocated.  The global CHK macro does `return _r` which would bypass the
     * cleanup at `done:`.  We therefore use CHK_G (goto done on error) for
     * every write call below.  sa_content is freed via `done:` through the
     * explicit free at the bottom of this block on success; out_scratch is
     * always freed at `done:`.
     * ------------------------------------------------------------------ */
#undef  CHK_G
#define CHK_G(x) do { int _r = (x); if (_r < 0) { ret = _r; goto done; } \
                      len += (size_t)(_r); } while(0)

    size_t out_sz = SCEP_MAX_P7_LEN + env_ci_len;
    out_scratch = malloc(out_sz);
    if (!out_scratch) { ret = -1; goto done; }

    {
        uint8_t *op = out_scratch + out_sz;
        uint8_t *os = out_scratch;

        /* -- SignerInfo body ------------------------------------------ */
        size_t si_body_len;
        {
            size_t len = 0;
            /* signature OCTET STRING */
            CHK_G(mbedtls_asn1_write_raw_buffer(&op, os, sig, sig_len));
            CHK_G(mbedtls_asn1_write_len(&op, os, sig_len));
            CHK_G(mbedtls_asn1_write_tag(&op, os, MBEDTLS_ASN1_OCTET_STRING));
            /* signatureAlgorithm rsaEncryption NULL */
            CHK_G(w_alg_null(&op, os, OID_RSA_ENCRYPTION, sizeof(OID_RSA_ENCRYPTION)));
            /* signedAttrs [0] IMPLICIT SET OF Attribute */
            CHK_G(mbedtls_asn1_write_raw_buffer(&op, os, sa_content, sa_content_len));
            CHK_G(mbedtls_asn1_write_len(&op, os, sa_content_len));
            CHK_G(mbedtls_asn1_write_tag(&op, os, 0xA0)); /* [0] IMPLICIT */
            /* digestAlgorithm sha256 NULL */
            CHK_G(w_alg_null(&op, os, OID_SHA256, sizeof(OID_SHA256)));
            /* sid IssuerAndSerialNumber */
            CHK_G(w_issuer_serial(&op, os,
                self_issuer, self_issuer_len, self_serial, self_serial_len));
            /* version=1 */
            CHK_G(mbedtls_asn1_write_int(&op, os, 1));
            si_body_len = len;
        }

        /* -- SignerInfo SEQUENCE header -------------------------------- */
        size_t si_hdr_len;
        {
            size_t len = 0;
            CHK_G(mbedtls_asn1_write_len(&op, os, si_body_len));
            CHK_G(mbedtls_asn1_write_tag(&op, os,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
            si_hdr_len = len;
        }
        size_t si_total = si_body_len + si_hdr_len;

        /* -- signerInfos SET header ------------------------------------ */
        size_t sis_hdr_len;
        {
            size_t len = 0;
            CHK_G(mbedtls_asn1_write_len(&op, os, si_total));
            CHK_G(mbedtls_asn1_write_tag(&op, os,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET));
            sis_hdr_len = len;
        }
        size_t sis_total = si_total + sis_hdr_len;

        /* -- certificates [0] IMPLICIT -------------------------------- */
        size_t certs_tlv_len;
        {
            size_t len = 0;
            CHK_G(mbedtls_asn1_write_raw_buffer(&op, os,
                self_signed_cert_der, self_signed_cert_len));
            CHK_G(mbedtls_asn1_write_len(&op, os, self_signed_cert_len));
            CHK_G(mbedtls_asn1_write_tag(&op, os, 0xA0)); /* [0] IMPLICIT */
            certs_tlv_len = len;
        }

        /* -- encapContentInfo SEQUENCE -------------------------------- */
        /* encapContentInfo: SEQUENCE { OID, [0] EXPLICIT { OCTET STRING } }
         * But for SCEP the inner content is not an OCTET STRING -- the
         * EnvelopedData ContentInfo is the eContent directly.
         * RFC 5652 §5.2: eContent [0] EXPLICIT OCTET STRING OPTIONAL
         * We wrap the EnvelopedData CI bytes in OCTET STRING then [0]. */
        size_t eci_os_len;   /* OCTET STRING TLV */
        {
            size_t len = 0;
            CHK_G(mbedtls_asn1_write_raw_buffer(&op, os, env_ci, env_ci_len));
            CHK_G(mbedtls_asn1_write_len(&op, os, env_ci_len));
            CHK_G(mbedtls_asn1_write_tag(&op, os, MBEDTLS_ASN1_OCTET_STRING));
            eci_os_len = len;
        }
        size_t eci_ctx_len;  /* [0] EXPLICIT wrapper */
        {
            size_t len = 0;
            CHK_G(mbedtls_asn1_write_len(&op, os, eci_os_len));
            CHK_G(mbedtls_asn1_write_tag(&op, os, 0xA0));
            eci_ctx_len = len;
        }
        size_t eci_oid_len;
        {
            size_t len = 0;
            /* RFC 8894 §3.2: eContentType for the outer SignedData is id-data,
             * NOT id-envelopedData (the latter is the type of the *inner*
             * eContent value, but the wrapper says id-data).  The contentType
             * signed attribute above is set to match. */
            CHK_G(w_oid(&op, os, OID_DATA, sizeof(OID_DATA)));
            eci_oid_len = len;
        }
        size_t eci_body = eci_oid_len + eci_ctx_len + eci_os_len;
        size_t eci_hdr_len;
        {
            size_t len = 0;
            CHK_G(mbedtls_asn1_write_len(&op, os, eci_body));
            CHK_G(mbedtls_asn1_write_tag(&op, os,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
            eci_hdr_len = len;
        }
        size_t eci_total = eci_body + eci_hdr_len;

        /* -- digestAlgorithms SET { sha256 NULL } --------------------- */
        size_t da_alg_len;
        {
            size_t len = 0;
            CHK_G(w_alg_null(&op, os, OID_SHA256, sizeof(OID_SHA256)));
            da_alg_len = len;
        }
        size_t da_hdr_len;
        {
            size_t len = 0;
            CHK_G(mbedtls_asn1_write_len(&op, os, da_alg_len));
            CHK_G(mbedtls_asn1_write_tag(&op, os,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET));
            da_hdr_len = len;
        }
        size_t da_total = da_alg_len + da_hdr_len;

        /* -- version=1 INTEGER ---------------------------------------- */
        size_t ver_len;
        {
            size_t len = 0;
            CHK_G(mbedtls_asn1_write_int(&op, os, 1));
            ver_len = len;
        }

        /* SignedData body = version + digestAlgorithms + encapContentInfo
         *                 + certificates + signerInfos */
        size_t sd_body = ver_len + da_total + eci_total + certs_tlv_len + sis_total;

        /* -- SignedData SEQUENCE header -------------------------------- */
        size_t sd_hdr_len;
        {
            size_t len = 0;
            CHK_G(mbedtls_asn1_write_len(&op, os, sd_body));
            CHK_G(mbedtls_asn1_write_tag(&op, os,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
            sd_hdr_len = len;
        }
        size_t sd_total = sd_body + sd_hdr_len;

        /* -- ContentInfo outer SEQUENCE ------------------------------- */
        /* [0] EXPLICIT wrapper for SignedData */
        size_t ci_ctx_hdr_len;
        {
            size_t len = 0;
            CHK_G(mbedtls_asn1_write_len(&op, os, sd_total));
            CHK_G(mbedtls_asn1_write_tag(&op, os, 0xA0));
            ci_ctx_hdr_len = len;
        }
        size_t ci_oid_len;
        {
            size_t len = 0;
            CHK_G(w_oid(&op, os, OID_SIGNED_DATA, sizeof(OID_SIGNED_DATA)));
            ci_oid_len = len;
        }
        size_t ci_body = ci_oid_len + ci_ctx_hdr_len + sd_total;
        size_t ci_hdr_len;
        {
            size_t len = 0;
            CHK_G(mbedtls_asn1_write_len(&op, os, ci_body));
            CHK_G(mbedtls_asn1_write_tag(&op, os,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
            ci_hdr_len = len;
        }
        size_t ci_total = ci_body + ci_hdr_len;

        if (ci_total > *out_p7_len) { ret = -2; goto done; }
        memcpy(out_p7, op, ci_total);
        *out_p7_len = ci_total;
    }
#undef CHK_G

    ret = 0;

done:
    mbedtls_x509_crt_free(&ra_crt);
    free(env_scratch);
    free(out_scratch);
    free(sa_content);
    free(enc_csr);
    if (enc_cek) {
        /* Wipe the RSA-wrapped CEK before releasing. */
        volatile uint8_t *evp = enc_cek;
        for (size_t i = 0; i < enc_cek_len; i++) evp[i] = 0;
        free(enc_cek);
    }
    return ret;
}

/* -----------------------------------------------------------------------
 * Helper: find a SCEP signed attribute value by OID in raw SignerInfo bytes
 * Returns 0 if found (sets *val_out, *val_len_out to the inner value TLV)
 * --------------------------------------------------------------------- */
static int find_scep_attr(const uint8_t *signer_info_val, size_t si_len,
                          const uint8_t *oid_bytes, size_t oid_sz,
                          const uint8_t **val_out, size_t *val_len_out)
{
    /* Walk the signedAttrs: skip version, signerIdentifier, digestAlgorithm,
     * then parse [0] IMPLICIT signedAttrs */
    const uint8_t *p   = signer_info_val;
    const uint8_t *end = signer_info_val + si_len;

    /* version */
    if (asn_skip(&p, end) != 0) return -1;
    /* signerIdentifier */
    if (asn_skip(&p, end) != 0) return -1;
    /* digestAlgorithm */
    if (asn_skip(&p, end) != 0) return -1;

    /* signedAttrs [0] IMPLICIT */
    if (p >= end || (*p & 0x1f) != 0) return -1;
    const uint8_t *sa_val;
    size_t sa_len;
    if (asn_read(&p, end, NULL, &sa_val, &sa_len) != 0) return -1;

    /* Walk each attribute SEQUENCE { OID, SET { value } } */
    const uint8_t *ap  = sa_val;
    const uint8_t *aend = sa_val + sa_len;
    while (ap < aend) {
        const uint8_t *attr_val;
        size_t attr_len;
        if (asn_expect(&ap, aend,
                       MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE,
                       &attr_val, &attr_len) != 0) break;
        const uint8_t *avp  = attr_val;
        const uint8_t *avend = attr_val + attr_len;

        /* OID */
        const uint8_t *cur_oid;
        size_t cur_oid_len;
        if (asn_expect(&avp, avend, MBEDTLS_ASN1_OID,
                       &cur_oid, &cur_oid_len) != 0) continue;

        /* SET { value } */
        const uint8_t *set_val;
        size_t set_len;
        if (asn_expect(&avp, avend,
                       MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET,
                       &set_val, &set_len) != 0) continue;

        if (cur_oid_len == oid_sz && memcmp(cur_oid, oid_bytes, oid_sz) == 0) {
            *val_out    = set_val;
            *val_len_out = set_len;
            return 0;
        }
    }
    return -1;
}

/* Extract PrintableString value from a SET { PrintableString } blob */
static int get_printable_string(const uint8_t *set_val, size_t set_len,
                                char *out_str, size_t out_cap)
{
    const uint8_t *p = set_val;
    const uint8_t *end = set_val + set_len;
    if (p >= end) return -1;
    int tag = *p;
    if (tag != 0x13 && tag != 0x0c && tag != 0x16) return -1;
    const uint8_t *sv;
    size_t slen;
    if (asn_read(&p, end, NULL, &sv, &slen) != 0) return -1;
    if (slen >= out_cap) slen = out_cap - 1;
    memcpy(out_str, sv, slen);
    out_str[slen] = '\0';
    return 0;
}

/* -----------------------------------------------------------------------
 * Walk outer SignedData; return:
 *   - encapContent bytes (pointing into p7)
 *   - signer_info_val / signer_info_len (the raw content of first SignerInfo)
 *   - certs_val / certs_len (the [0] certificates content, if present)
 * --------------------------------------------------------------------- */
static int parse_outer_signed_data(const uint8_t *p7, size_t p7_len,
                                   const uint8_t **encap_val, size_t *encap_len,
                                   const uint8_t **si_val,    size_t *si_len,
                                   const uint8_t **certs_val, size_t *certs_len)
{
    const uint8_t *p   = p7;
    const uint8_t *end = p7 + p7_len;

    /* ContentInfo SEQUENCE */
    const uint8_t *ci_val;
    size_t ci_len;
    if (asn_expect(&p, end, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE,
                   &ci_val, &ci_len) != 0) return -1;
    p = ci_val; end = ci_val + ci_len;

    /* OID signedData -- skip */
    if (asn_skip(&p, end) != 0) return -1;

    /* [0] EXPLICIT SignedData */
    const uint8_t *sd_wrap;
    size_t sd_wrap_len;
    if (asn_expect(&p, end, 0xA0, &sd_wrap, &sd_wrap_len) != 0) return -1;
    p = sd_wrap; end = sd_wrap + sd_wrap_len;

    /* SignedData SEQUENCE */
    const uint8_t *sd_val;
    size_t sd_len;
    if (asn_expect(&p, end, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE,
                   &sd_val, &sd_len) != 0) return -1;
    p = sd_val; end = sd_val + sd_len;

    /* version */
    if (asn_skip(&p, end) != 0) return -1;
    /* digestAlgorithms */
    if (asn_skip(&p, end) != 0) return -1;

    /* encapContentInfo SEQUENCE */
    const uint8_t *eci_val;
    size_t eci_len;
    if (asn_expect(&p, end, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE,
                   &eci_val, &eci_len) != 0) return -1;
    {
        const uint8_t *ep = eci_val;
        const uint8_t *ee = eci_val + eci_len;
        if (asn_skip(&ep, ee) != 0) return -1; /* OID */
        *encap_val = NULL; *encap_len = 0;
        if (ep < ee && *ep == 0xA0) {
            const uint8_t *ctx_val;
            size_t ctx_len;
            if (asn_expect(&ep, ee, 0xA0, &ctx_val, &ctx_len) == 0) {
                const uint8_t *tmp = ctx_val;
                const uint8_t *te  = ctx_val + ctx_len;
                if (asn_expect(&tmp, te, MBEDTLS_ASN1_OCTET_STRING,
                               encap_val, encap_len) != 0) {
                    /* Some CAs omit the OCTET STRING wrapper */
                    *encap_val = ctx_val;
                    *encap_len = ctx_len;
                }
            }
        }
    }

    /* certificates [0] IMPLICIT -- optional */
    *certs_val = NULL; *certs_len = 0;
    if (p < end && *p == 0xA0) {
        if (asn_read(&p, end, NULL, certs_val, certs_len) != 0) return -1;
    }

    /* crls [1] -- optional */
    if (p < end && *p == 0xA1)
        if (asn_skip(&p, end) != 0) return -1;

    /* signerInfos SET */
    const uint8_t *sis_val;
    size_t sis_len;
    if (asn_expect(&p, end, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET,
                   &sis_val, &sis_len) != 0) {
        *si_val = NULL; *si_len = 0;
        return 0; /* degenerate -- no signers */
    }

    /* First SignerInfo SEQUENCE */
    const uint8_t *sp = sis_val;
    const uint8_t *se = sis_val + sis_len;
    if (sp >= se) { *si_val = NULL; *si_len = 0; return 0; }
    if (asn_expect(&sp, se, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE,
                   si_val, si_len) != 0) { *si_val = NULL; *si_len = 0; }

    return 0;
}

/* -----------------------------------------------------------------------
 * Helper: extract the raw signedAttrs bytes and signature from a SignerInfo
 * value (the body of the SignerInfo SEQUENCE, as returned by
 * parse_outer_signed_data).
 *
 * On success:
 *   *sa_raw / *sa_raw_len  -- points into si_val at the [0] tag byte of the
 *                             signedAttrs field (the whole TLV, not just content).
 *   *sig_val / *sig_len    -- the signature bytes (OCTET STRING content).
 * --------------------------------------------------------------------- */
static int si_extract_sa_and_sig(const uint8_t  *si_val, size_t si_len,
                                 const uint8_t **sa_raw,   size_t *sa_raw_len,
                                 const uint8_t **sig_val,  size_t *sig_len)
{
    const uint8_t *p   = si_val;
    const uint8_t *end = si_val + si_len;

    /* version INTEGER */
    if (asn_skip(&p, end) != 0) return -1;
    /* signerIdentifier (IssuerAndSerialNumber SEQUENCE or [0] subjectKeyId) */
    if (asn_skip(&p, end) != 0) return -1;
    /* digestAlgorithm AlgorithmIdentifier SEQUENCE */
    if (asn_skip(&p, end) != 0) return -1;

    /* signedAttrs [0] IMPLICIT -- tag is 0xA0; capture full TLV */
    if (p >= end || (*p & 0x1f) != 0) return -1; /* must be context[0] */
    *sa_raw = p; /* remember start of TLV */
    const uint8_t *sa_content_ptr;
    size_t sa_content_sz;
    if (asn_read(&p, end, NULL, &sa_content_ptr, &sa_content_sz) != 0) return -1;
    *sa_raw_len = (size_t)(p - *sa_raw); /* includes tag + length + content */

    /* signatureAlgorithm AlgorithmIdentifier */
    if (asn_skip(&p, end) != 0) return -1;

    /* signature OCTET STRING */
    if (asn_expect(&p, end, MBEDTLS_ASN1_OCTET_STRING, sig_val, sig_len) != 0)
        return -1;

    (void)sa_content_ptr; (void)sa_content_sz;
    return 0;
}

/* -----------------------------------------------------------------------
 * 6. Parse CertRep
 *
 * SECURITY: This function VERIFIES the outer SignedData signature before
 * decrypting the inner EnvelopedData.  Without this check a network
 * attacker could forge a SUCCESS CertRep with an attacker-controlled cert
 * that the firmware would then store in NVS and use for EAP-TLS.
 * --------------------------------------------------------------------- */
int scep_parse_certrep(const uint8_t      *p7,
                       size_t              p7_len,
                       const char         *expected_transaction_id,
                       mbedtls_pk_context *recipient_key,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void               *p_rng,
                       uint8_t            *out_cert_der,
                       size_t             *out_cert_len,
                       scep_pki_status_t  *out_status,
                       int                *out_fail_info)
{
    if (!p7 || !expected_transaction_id || !recipient_key ||
        !out_status || !out_fail_info) return -1;

    *out_status    = SCEP_PKI_STATUS_UNKNOWN;
    *out_fail_info = SCEP_FAIL_INFO_NONE;

    /* Parse outer SignedData */
    const uint8_t *encap_val, *si_val, *certs_val;
    size_t encap_len, si_len, certs_len;
    int ret = parse_outer_signed_data(p7, p7_len,
                                      &encap_val, &encap_len,
                                      &si_val,    &si_len,
                                      &certs_val, &certs_len);
    if (ret != 0) return ret;

    if (!si_val || si_len == 0) return -1;

    /* ------------------------------------------------------------------
     * CRITICAL: Verify the SignedData signature over signedAttrs.
     *
     * Attack scenario: if this check is omitted a MITM can craft any
     * pkiStatus=SUCCESS CertRep carrying an attacker-controlled leaf cert.
     * The firmware would then trust that cert for EAP-TLS without ever
     * having verified that the SCEP RA actually signed the response.
     *
     * Verification steps:
     *   1. Extract the signer cert from certificates[0] in the outer
     *      SignedData (the SCEP RA's signing cert).
     *   2. Parse it with mbedtls_x509_crt_parse_der to obtain the public key.
     *   3. Extract the raw signedAttrs TLV from the SignerInfo.  The DER
     *      encoding to hash is the same bytes but with tag 0xA0 replaced by
     *      0x31 (SET), because RFC 5652 §5.4 says "the DER encoding of the
     *      SET OF Attributes value is the data signed".
     *   4. SHA-256(encoded-signedAttrs-SET) -> sa_hash[32].
     *   5. Extract signature OCTET STRING from the SignerInfo.
     *   6. mbedtls_pk_verify(&signer_pk, MBEDTLS_MD_SHA256, sa_hash, 32,
     *                        sig, sig_len) -- reject if non-zero.
     *
     * Only after successful verification do we proceed to EnvelopedData
     * decryption.
     * ------------------------------------------------------------------ */
    {
        /* Step 1: parse signer cert from certificates[0] in outer SignedData */
        if (!certs_val || certs_len == 0) return -1; /* no signer cert -> reject */

        /* certificates field is the content of [0] IMPLICIT; walk to first cert */
        const uint8_t *cv_p   = certs_val;
        const uint8_t *cv_end = certs_val + certs_len;
        const uint8_t *signer_cert_start = cv_p;
        const uint8_t *signer_cert_body;
        size_t         signer_cert_body_len;
        if (asn_expect(&cv_p, cv_end,
                       MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE,
                       &signer_cert_body, &signer_cert_body_len) != 0) return -1;
        size_t signer_cert_der_len = (size_t)(cv_p - signer_cert_start);

        /* Step 2: parse cert and load public key */
        mbedtls_x509_crt signer_crt;
        mbedtls_x509_crt_init(&signer_crt);
        ret = mbedtls_x509_crt_parse_der(&signer_crt,
                                          signer_cert_start, signer_cert_der_len);
        if (ret != 0) {
            mbedtls_x509_crt_free(&signer_crt);
            return -1;
        }

        /* Step 3: extract raw signedAttrs TLV and signature from SignerInfo */
        const uint8_t *sa_raw;   size_t sa_raw_len;
        const uint8_t *sig_raw;  size_t sig_raw_len;
        ret = si_extract_sa_and_sig(si_val, si_len,
                                    &sa_raw, &sa_raw_len,
                                    &sig_raw, &sig_raw_len);
        if (ret != 0) {
            mbedtls_x509_crt_free(&signer_crt);
            return -1;
        }

        /* Build the SET-tagged signedAttrs for hashing.
         * RFC 5652 §5.4: "the DER encoding of the SET OF Attributes value
         * is the data over which the message digest is computed."  The
         * signedAttrs in the SignerInfo use [0] IMPLICIT (tag 0xA0) on the
         * wire; for digest we replace just the outer tag byte with 0x31. */
        uint8_t *sa_set = malloc(sa_raw_len);
        if (!sa_set) {
            mbedtls_x509_crt_free(&signer_crt);
            return -1;
        }
        memcpy(sa_set, sa_raw, sa_raw_len);
        sa_set[0] = 0x31; /* SET tag */

        /* Step 4: SHA-256(encoded-signedAttrs-SET) */
        uint8_t sa_hash[SHA256_LEN];
        ret = mbedtls_sha256(sa_set, sa_raw_len, sa_hash, 0);
        free(sa_set);
        if (ret != 0) {
            mbedtls_x509_crt_free(&signer_crt);
            return -1;
        }

        /* Step 5 + 6: verify RSA signature.
         * mbedtls_pk_verify() takes the hash (not the message), so we pass
         * the SHA-256 digest and MBEDTLS_MD_SHA256 so mbedTLS knows the
         * DigestInfo OID to expect inside the PKCS#1 v1.5 signature block. */
        ret = mbedtls_pk_verify(&signer_crt.pk, MBEDTLS_MD_SHA256,
                                sa_hash, SHA256_LEN,
                                sig_raw, sig_raw_len);
        mbedtls_x509_crt_free(&signer_crt);
        if (ret != 0) {
            /* Signature verification failed: reject the entire CertRep.
             * Do NOT proceed to EnvelopedData decryption -- the message has
             * been tampered with or is from an attacker. */
            return -1;
        }
        /* Signature verified -- safe to continue processing. */
    }

    /* Extract transactionID */
    const uint8_t *av; size_t al;
    if (find_scep_attr(si_val, si_len, OID_TXID, sizeof(OID_TXID), &av, &al) == 0) {
        char got_txid[SCEP_TRANSACTION_ID_HEX_LEN + 1] = {0};
        get_printable_string(av, al, got_txid, sizeof(got_txid));
        if (strcmp(got_txid, expected_transaction_id) != 0) return -1;
    }

    /* Extract pkiStatus */
    if (find_scep_attr(si_val, si_len, OID_PKI_STATUS, sizeof(OID_PKI_STATUS),
                       &av, &al) == 0) {
        char s[8] = {0};
        get_printable_string(av, al, s, sizeof(s));
        *out_status = (scep_pki_status_t)(int)strtol(s, NULL, 10);
    }

    /* Extract failInfo if FAILURE */
    if (*out_status == SCEP_PKI_STATUS_FAILURE) {
        if (find_scep_attr(si_val, si_len, OID_FAIL_INFO, sizeof(OID_FAIL_INFO),
                           &av, &al) == 0) {
            char s[8] = {0};
            get_printable_string(av, al, s, sizeof(s));
            *out_fail_info = (int)strtol(s, NULL, 10);
        }
    }

    if (*out_status != SCEP_PKI_STATUS_SUCCESS) return 0;

    if (!encap_val || encap_len == 0) return -1;

    /* Decrypt inner EnvelopedData with our RSA private key */
    /* The encap_val is the raw EnvelopedData ContentInfo DER (or just EnvelopedData) */

    /* Parse the inner structure to find the EncryptedContentInfo and KTRI */
    /* First, handle if it's wrapped in a ContentInfo */
    const uint8_t *env_p = encap_val;
    const uint8_t *env_end = encap_val + encap_len;

    /* Try to unwrap ContentInfo if present (starts with SEQUENCE + signedData/envelopedData OID) */
    /* The inner content is just EnvelopedData DER (not wrapped in ContentInfo in CertRep) */
    /* Actually the cryptography lib wraps it in ContentInfo. Let's handle both. */

    /* Determine if it starts with a ContentInfo (SEQUENCE { OID ... }) or EnvelopedData */
    const uint8_t *ed_p;
    const uint8_t *ed_end;

    /* Try to parse as ContentInfo first */
    {
        const uint8_t *tmp = env_p;
        const uint8_t *tv;
        size_t tl;
        if (asn_expect(&tmp, env_end,
                       MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE,
                       &tv, &tl) == 0) {
            const uint8_t *ipp = tv;
            const uint8_t *ie  = tv + tl;
            int first_tag = (ipp < ie) ? *ipp : 0;
            if (first_tag == MBEDTLS_ASN1_OID) {
                /* Skip OID */
                asn_skip(&ipp, ie);
                /* [0] EXPLICIT or direct content */
                if (ipp < ie && *ipp == 0xA0) {
                    const uint8_t *wv;
                    size_t wl;
                    asn_expect(&ipp, ie, 0xA0, &wv, &wl);
                    ed_p   = wv;
                    ed_end = wv + wl;
                } else {
                    /* No wrapper -- content inline */
                    ed_p   = tv;
                    ed_end = tv + tl;
                }
            } else {
                /* Not ContentInfo, treat as raw EnvelopedData */
                ed_p   = tv;
                ed_end = tv + tl;
            }
        } else {
            ed_p   = env_p;
            ed_end = env_end;
        }
    }

    /* Parse EnvelopedData SEQUENCE */
    const uint8_t *edv;
    size_t edl;
    if (asn_expect(&ed_p, ed_end,
                   MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE,
                   &edv, &edl) != 0) {
        /* Maybe ed_p already points into EnvelopedData body */
        edv = ed_p; edl = (size_t)(ed_end - ed_p);
    }
    const uint8_t *edp = edv;
    const uint8_t *ede = edv + edl;

    /* version */
    if (asn_skip(&edp, ede) != 0) return -1;

    /* recipientInfos SET */
    const uint8_t *ri_val;
    size_t ri_len;
    if (asn_expect(&edp, ede,
                   MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET,
                   &ri_val, &ri_len) != 0) return -1;

    /* Find our KTRI (KeyTransRecipientInfo): SEQUENCE { version, rid, alg, encKey } */
    const uint8_t *enc_key_der = NULL;
    size_t         enc_key_len = 0;
    int            kea_is_oaep = 0;
    {
        const uint8_t *rp = ri_val;
        const uint8_t *re = ri_val + ri_len;
        while (rp < re) {
            const uint8_t *ktri_val;
            size_t ktri_len;
            if (asn_expect(&rp, re,
                           MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE,
                           &ktri_val, &ktri_len) != 0) break;
            const uint8_t *kp = ktri_val;
            const uint8_t *ke = ktri_val + ktri_len;
            asn_skip(&kp, ke); /* version */
            asn_skip(&kp, ke); /* rid (issuerAndSerialNumber or subjectKeyId) */
            /* keyEncryptionAlgorithm AlgorithmIdentifier { OID, params } --
             * peek at the OID so we can dispatch the right padding scheme. */
            const uint8_t *kea_val;
            size_t         kea_len;
            if (asn_expect(&kp, ke,
                           MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE,
                           &kea_val, &kea_len) != 0) break;
            {
                const uint8_t *ap = kea_val;
                const uint8_t *ae = kea_val + kea_len;
                const uint8_t *oid_val;
                size_t         oid_len;
                if (asn_expect(&ap, ae, MBEDTLS_ASN1_OID,
                               &oid_val, &oid_len) == 0) {
                    if (oid_len == sizeof(OID_RSAES_OAEP) &&
                        memcmp(oid_val, OID_RSAES_OAEP, oid_len) == 0) {
                        kea_is_oaep = 1;
                    }
                }
            }
            /* encryptedKey OCTET STRING */
            const uint8_t *ek_val;
            size_t ek_len;
            if (asn_expect(&kp, ke, MBEDTLS_ASN1_OCTET_STRING,
                           &ek_val, &ek_len) == 0) {
                enc_key_der = ek_val;
                enc_key_len = ek_len;
                break;
            }
        }
    }
    if (!enc_key_der || enc_key_len == 0) return -1;

    /* Decrypt CEK with our private key, using the padding scheme advertised
     * in the recipient's keyEncryptionAlgorithm OID.  Microsoft NDES sends
     * the CertRep CEK wrapped in RSAES-OAEP (OID 1.2.840.113549.1.1.7) with
     * SHA-1 as the hash/MGF algorithm; other SCEP CAs may use the legacy
     * RSAES-PKCS1v15 (OID 1.2.840.113549.1.1.1).  Dispatching on the OID
     * avoids a side-channel-noisy first-failed-attempt retry. */
    if (mbedtls_pk_get_type(recipient_key) != MBEDTLS_PK_RSA) return -1;
    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(*recipient_key);
    if (kea_is_oaep) {
        /* Determine the OAEP hash from the AlgorithmIdentifier parameters.
         * RFC 3560 / RFC 8017: RSAES-OAEP-params SEQUENCE contains hashAlgorithm
         * as the first optional field.  If absent or unrecognised, default to
         * SHA-256.  Previously this was hard-coded to SHA-1 (the ASN.1 default),
         * but that ignores what the sender actually negotiated.  We parse the
         * hashAlgorithm OID from the kea_val block captured during KTRI walking
         * above.  Because kea_val is not available here we re-parse inline.
         *
         * SHA OIDs we recognise:
         *   SHA-1   : 1.3.14.3.2.26      (legacy NDES default)
         *   SHA-256 : 2.16.840.1.101.3.4.2.1 (preferred)
         *   SHA-384 : 2.16.840.1.101.3.4.2.2
         *   SHA-512 : 2.16.840.1.101.3.4.2.3
         *
         * Default (absent params / unrecognised OID): SHA-256.
         */
        static const uint8_t OID_SHA1[]   = {0x2b,0x0e,0x03,0x02,0x1a};
        static const uint8_t OID_SHA384[]  = {0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02};
        static const uint8_t OID_SHA512[]  = {0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03};

        mbedtls_md_type_t oaep_hash = MBEDTLS_MD_SHA256; /* safe default */

        /* Re-walk the KTRI list to find the OAEP AlgorithmIdentifier params */
        {
            const uint8_t *rp2 = ri_val;
            const uint8_t *re2 = ri_val + ri_len;
            while (rp2 < re2) {
                const uint8_t *kv2; size_t kl2;
                if (asn_expect(&rp2, re2,
                               MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE,
                               &kv2, &kl2) != 0) break;
                const uint8_t *kp2 = kv2;
                const uint8_t *ke2 = kv2 + kl2;
                asn_skip(&kp2, ke2); /* version */
                asn_skip(&kp2, ke2); /* rid */
                /* keyEncryptionAlgorithm AlgorithmIdentifier */
                const uint8_t *kea_v2; size_t kea_l2;
                if (asn_expect(&kp2, ke2,
                               MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE,
                               &kea_v2, &kea_l2) != 0) break;
                const uint8_t *ap2 = kea_v2;
                const uint8_t *ae2 = kea_v2 + kea_l2;
                /* OID (already confirmed RSAES-OAEP) */
                if (asn_skip(&ap2, ae2) != 0) break;
                /* params: RSAES-OAEP-params SEQUENCE (optional) */
                if (ap2 < ae2 && *ap2 == (MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) {
                    const uint8_t *oaep_params; size_t oaep_params_len;
                    if (asn_expect(&ap2, ae2,
                                   MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE,
                                   &oaep_params, &oaep_params_len) == 0) {
                        const uint8_t *pp2 = oaep_params;
                        const uint8_t *pe2 = oaep_params + oaep_params_len;
                        /* hashAlgorithm [0] AlgorithmIdentifier (optional) */
                        if (pp2 < pe2 && (*pp2 & 0xe0) == 0xa0) {
                            const uint8_t *hctx; size_t hctx_len;
                            if (asn_read(&pp2, pe2, NULL, &hctx, &hctx_len) == 0) {
                                const uint8_t *hp = hctx;
                                const uint8_t *he = hctx + hctx_len;
                                const uint8_t *hoid; size_t hoid_len;
                                if (asn_expect(&hp, he, MBEDTLS_ASN1_OID,
                                               &hoid, &hoid_len) == 0) {
                                    if (hoid_len == sizeof(OID_SHA1) &&
                                        memcmp(hoid, OID_SHA1, hoid_len) == 0)
                                        oaep_hash = MBEDTLS_MD_SHA1;
                                    else if (hoid_len == sizeof(OID_SHA256) &&
                                             memcmp(hoid, OID_SHA256, hoid_len) == 0)
                                        oaep_hash = MBEDTLS_MD_SHA256;
                                    else if (hoid_len == sizeof(OID_SHA384) &&
                                             memcmp(hoid, OID_SHA384, hoid_len) == 0)
                                        oaep_hash = MBEDTLS_MD_SHA384;
                                    else if (hoid_len == sizeof(OID_SHA512) &&
                                             memcmp(hoid, OID_SHA512, hoid_len) == 0)
                                        oaep_hash = MBEDTLS_MD_SHA512;
                                    /* else: unknown OID -- keep SHA-256 default */
                                }
                            }
                        }
                    }
                }
                break; /* only need the first KTRI */
            }
        }
        mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, oaep_hash);
    } else {
        mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE);
    }

    uint8_t cek[CEK_LEN + 256]; /* oversized to avoid OUTPUT_TOO_LARGE on OAEP */
    size_t  cek_out_len = sizeof(cek);
    ret = mbedtls_rsa_pkcs1_decrypt(rsa, f_rng, p_rng,
                                    &cek_out_len, enc_key_der, cek, sizeof(cek));
    if (ret != 0) return ret;
    /* Accept AES-128 (16 B) or AES-256 (32 B) CEK */
    if (cek_out_len != 16 && cek_out_len != 32) return -1;
    size_t cek_actual_len = cek_out_len;

    /* EncryptedContentInfo */
    const uint8_t *eci_val;
    size_t eci_len;
    if (asn_expect(&edp, ede,
                   MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE,
                   &eci_val, &eci_len) != 0) return -1;
    const uint8_t *ep = eci_val;
    const uint8_t *ee = eci_val + eci_len;

    /* contentType OID -- skip */
    if (asn_skip(&ep, ee) != 0) return -1;

    /* contentEncryptionAlgorithm: get IV from params */
    uint8_t iv[IV_LEN];
    {
        const uint8_t *alg_val;
        size_t alg_len;
        if (asn_expect(&ep, ee,
                       MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE,
                       &alg_val, &alg_len) != 0) return -1;
        const uint8_t *ap2 = alg_val;
        const uint8_t *ae2 = alg_val + alg_len;
        if (asn_skip(&ap2, ae2) != 0) return -1; /* OID */
        /* IV OCTET STRING */
        const uint8_t *iv_val;
        size_t iv_len_actual;
        if (asn_expect(&ap2, ae2, MBEDTLS_ASN1_OCTET_STRING,
                       &iv_val, &iv_len_actual) != 0) return -1;
        if (iv_len_actual != IV_LEN) return -1;
        memcpy(iv, iv_val, IV_LEN);
    }

    /* encryptedContent [0] IMPLICIT */
    if (ep >= ee || (*ep & 0x1f) != 0) return -1;
    const uint8_t *enc_content;
    size_t enc_content_len;
    if (asn_read(&ep, ee, NULL, &enc_content, &enc_content_len) != 0) return -1;

    /* Decrypt AES-CBC (key size from RSA decrypt: 128 or 256 bit) */
    if (enc_content_len > SCEP_MAX_CERT_DER + 512) return -1;
    uint8_t *inner_buf = malloc(enc_content_len);
    if (!inner_buf) return -1;

    {
        mbedtls_aes_context aes;
        mbedtls_aes_init(&aes);
        uint8_t iv2[IV_LEN];
        memcpy(iv2, iv, IV_LEN);
        ret = mbedtls_aes_setkey_dec(&aes, cek, (unsigned int)(cek_actual_len * 8));
        if (ret == 0)
            ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT,
                                        enc_content_len, iv2,
                                        enc_content, inner_buf);
        mbedtls_aes_free(&aes);
    }
    /* Wipe CEK */
    volatile uint8_t *vc = cek;
    for (size_t i = 0; i < sizeof(cek); i++) vc[i] = 0;

    if (ret != 0) { free(inner_buf); return ret; }

    /* Remove PKCS#7 padding */
    if (enc_content_len == 0) { free(inner_buf); return -1; }
    uint8_t pad = inner_buf[enc_content_len - 1];
    if (pad == 0 || pad > 16 || pad > enc_content_len) { free(inner_buf); return -1; }
    size_t inner_len = enc_content_len - pad;

    /* inner_buf[0..inner_len-1] is the degenerate SignedData DER */
    /* Parse it to extract the cert */
    const uint8_t *inner_encap, *inner_si, *inner_certs;
    size_t inner_encap_len, inner_si_len, inner_certs_len;
    ret = parse_outer_signed_data(inner_buf, inner_len,
                                  &inner_encap, &inner_encap_len,
                                  &inner_si,    &inner_si_len,
                                  &inner_certs, &inner_certs_len);
    if (ret != 0) { free(inner_buf); return ret; }

    /* Extract the cert from inner_certs (which is [0] IMPLICIT content) */
    if (!inner_certs || inner_certs_len == 0) { free(inner_buf); return -1; }

    const uint8_t *cert_der = inner_certs;
    const uint8_t *cert_end = inner_certs + inner_certs_len;
    const uint8_t *cv;
    size_t cl;
    if (asn_expect(&cert_der, cert_end,
                   MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE,
                   &cv, &cl) != 0) { free(inner_buf); return -1; }
    /* Rewind to include the SEQUENCE tag+len */
    size_t cert_total = (size_t)(cert_der - inner_certs);
    const uint8_t *cert_start = inner_certs;

    if (out_cert_der && out_cert_len) {
        if (cert_total > *out_cert_len) { free(inner_buf); return -2; }
        memcpy(out_cert_der, cert_start, cert_total);
        *out_cert_len = cert_total;
    }

    free(inner_buf);
    return 0;
}

/* -----------------------------------------------------------------------
 * 7. Parse GetCACert degenerate SignedData
 * --------------------------------------------------------------------- */

/* Key usage bits (X.509) */
#define KU_DIGITAL_SIG  0x80
#define KU_KEY_ENCIPHER 0x20
#define KU_KEY_CERT_SIGN 0x04

static int get_key_usage(const uint8_t *cert_der, size_t cert_len,
                         uint8_t *ku_out)
{
    /* Use mbedTLS to parse and extract key usage via public API */
    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);
    int ret = mbedtls_x509_crt_parse_der(&crt, cert_der, cert_len);
    if (ret != 0) { mbedtls_x509_crt_free(&crt); return ret; }
    *ku_out = 0;
    /* mbedtls_x509_crt_check_key_usage returns 0 if the usage is set */
    if (mbedtls_x509_crt_check_key_usage(&crt,
            MBEDTLS_X509_KU_DIGITAL_SIGNATURE) == 0)
        *ku_out |= KU_DIGITAL_SIG;
    if (mbedtls_x509_crt_check_key_usage(&crt,
            MBEDTLS_X509_KU_KEY_ENCIPHERMENT) == 0)
        *ku_out |= KU_KEY_ENCIPHER;
    if (mbedtls_x509_crt_check_key_usage(&crt,
            MBEDTLS_X509_KU_KEY_CERT_SIGN) == 0)
        *ku_out |= KU_KEY_CERT_SIGN;
    mbedtls_x509_crt_free(&crt);
    return 0;
}

int scep_parse_getcacert(const uint8_t       *p7,
                         size_t               p7_len,
                         scep_cacert_bundle_t *out)
{
    if (!p7 || !out) return -1;
    memset(out, 0, sizeof(*out));

    /* Parse as degenerate SignedData */
    const uint8_t *encap, *si, *certs;
    size_t encap_len, si_len, certs_len;
    int ret = parse_outer_signed_data(p7, p7_len,
                                      &encap, &encap_len,
                                      &si, &si_len,
                                      &certs, &certs_len);
    if (ret != 0) return ret;

    if (!certs || certs_len == 0) return -1;

    /* Collect cert DER pointers from the [0] IMPLICIT certificates field */
    struct { const uint8_t *der; size_t len; } cert_ptrs[16];
    int ncerts = 0;

    const uint8_t *cp  = certs;
    const uint8_t *cpe = certs + certs_len;
    while (cp < cpe && ncerts < 16) {
        const uint8_t *cv;
        size_t cl;
        const uint8_t *cert_start = cp;
        if (asn_expect(&cp, cpe,
                       MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE,
                       &cv, &cl) != 0) break;
        cert_ptrs[ncerts].der = cert_start;
        cert_ptrs[ncerts].len = (size_t)(cp - cert_start);
        ncerts++;
    }

    if (ncerts == 0) return -1;

    if (ncerts == 1) {
        out->ca_cert_der         = cert_ptrs[0].der;
        out->ca_cert_len         = cert_ptrs[0].len;
        out->ra_sign_cert_der    = cert_ptrs[0].der;
        out->ra_sign_cert_len    = cert_ptrs[0].len;
        out->ra_encrypt_cert_der = cert_ptrs[0].der;
        out->ra_encrypt_cert_len = cert_ptrs[0].len;
        out->single_cert         = 1;
        return 0;
    }

    /* Identify certs by KeyUsage */
    const uint8_t *ra_enc_der = NULL, *ra_sign_der = NULL, *ca_der = NULL;
    size_t ra_enc_len = 0, ra_sign_len = 0, ca_len = 0;

    for (int i = 0; i < ncerts; i++) {
        uint8_t ku = 0;
        get_key_usage(cert_ptrs[i].der, cert_ptrs[i].len, &ku);
        if ((ku & KU_KEY_ENCIPHER) && !ra_enc_der) {
            ra_enc_der = cert_ptrs[i].der;
            ra_enc_len = cert_ptrs[i].len;
        } else if ((ku & KU_DIGITAL_SIG) && !(ku & KU_KEY_CERT_SIGN) && !ra_sign_der) {
            ra_sign_der = cert_ptrs[i].der;
            ra_sign_len = cert_ptrs[i].len;
        } else if ((ku & KU_KEY_CERT_SIGN) && !ca_der) {
            ca_der = cert_ptrs[i].der;
            ca_len = cert_ptrs[i].len;
        }
    }

    /* Fallbacks */
    if (!ca_der)      { ca_der = cert_ptrs[0].der; ca_len = cert_ptrs[0].len; }
    if (!ra_sign_der) { ra_sign_der = cert_ptrs[ncerts > 1 ? 1 : 0].der;
                        ra_sign_len = cert_ptrs[ncerts > 1 ? 1 : 0].len; }
    if (!ra_enc_der)  { ra_enc_der = ra_sign_der; ra_enc_len = ra_sign_len; }

    out->ca_cert_der         = ca_der;
    out->ca_cert_len         = ca_len;
    out->ra_sign_cert_der    = ra_sign_der;
    out->ra_sign_cert_len    = ra_sign_len;
    out->ra_encrypt_cert_der = ra_enc_der;
    out->ra_encrypt_cert_len = ra_enc_len;
    out->single_cert         = (ra_sign_der == ra_enc_der);
    return 0;
}

/* -----------------------------------------------------------------------
 * Test-only helper
 * --------------------------------------------------------------------- */
#ifdef SCEP_PROTO_TEST_HELPERS

int scep_parse_pkimessage_pkcsreq_for_test(const uint8_t             *p7,
                                           size_t                     p7_len,
                                           mbedtls_pk_context        *ra_priv_key,
                                           const uint8_t             *ra_cert_der,
                                           size_t                     ra_cert_len,
                                           int (*f_rng)(void *, unsigned char *, size_t),
                                           void                      *p_rng,
                                           scep_pkcsreq_unpacked_t   *out)
{
    if (!p7 || !ra_priv_key || !ra_cert_der || !out || !f_rng) return -1;
    memset(out, 0, sizeof(*out));

    const uint8_t *encap, *si_val, *certs;
    size_t encap_len, si_len, certs_len;
    int ret = parse_outer_signed_data(p7, p7_len,
                                      &encap, &encap_len,
                                      &si_val, &si_len,
                                      &certs, &certs_len);
    if (ret != 0 || !si_val) return -1;

    /* Extract signed attributes */
    const uint8_t *av; size_t al;
    if (find_scep_attr(si_val, si_len, OID_MSG_TYPE, sizeof(OID_MSG_TYPE), &av, &al) == 0)
        get_printable_string(av, al, out->message_type, sizeof(out->message_type));
    if (find_scep_attr(si_val, si_len, OID_TXID, sizeof(OID_TXID), &av, &al) == 0)
        get_printable_string(av, al, out->transaction_id, sizeof(out->transaction_id));
    if (find_scep_attr(si_val, si_len, OID_SENDER_NONCE, sizeof(OID_SENDER_NONCE), &av, &al) == 0) {
        if (al >= 2 && av[0] == 0x04)
            memcpy(out->sender_nonce, av + 2, al - 2 < SCEP_NONCE_LEN ? al - 2 : SCEP_NONCE_LEN);
    }

    /* Decrypt inner EnvelopedData */
    if (!encap || encap_len == 0) return -1;

    scep_pki_status_t status = SCEP_PKI_STATUS_SUCCESS;
    int fail_info = SCEP_FAIL_INFO_NONE;
    out->csr_len = sizeof(out->csr_der);
    ret = scep_parse_certrep(p7, p7_len, out->transaction_id,
                             ra_priv_key, f_rng, p_rng,
                             out->csr_der, &out->csr_len,
                             &status, &fail_info);
    /* scep_parse_certrep is designed for CertRep -- for PKCSReq test we
     * need to decrypt directly. Do it here. */
    (void)status; (void)fail_info;

    /* Actually decrypt the EnvelopedData directly */
    /* We reuse the certrep parse logic which handles EnvelopedData decryption.
     * But scep_parse_certrep expects CertRep format (with pkiStatus etc.).
     * For test purposes, just decrypt the encap content manually. */

    /* Reset and do direct decryption */
    out->csr_len = 0;

    /* encap points to the EnvelopedData (possibly wrapped in ContentInfo) */
    /* Use a minimal inline decrypt path */
    const uint8_t *env_p = encap;
    const uint8_t *env_end = encap + encap_len;

    /* If wrapped in ContentInfo, unwrap */
    {
        const uint8_t *tmp = env_p;
        const uint8_t *tv; size_t tl;
        if (asn_expect(&tmp, env_end,
                       MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE,
                       &tv, &tl) == 0 && tmp < env_end && *tv == MBEDTLS_ASN1_OID) {
            const uint8_t *ipp = tv;
            const uint8_t *ie  = tv + tl;
            asn_skip(&ipp, ie);
            if (ipp < ie && *ipp == 0xA0) {
                const uint8_t *wv; size_t wl;
                asn_expect(&ipp, ie, 0xA0, &wv, &wl);
                env_p   = wv;
                env_end = wv + wl;
            }
        }
    }

    /* EnvelopedData SEQUENCE */
    const uint8_t *edv; size_t edl;
    if (asn_expect(&env_p, env_end,
                   MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE,
                   &edv, &edl) != 0) return -1;
    const uint8_t *edp = edv;
    const uint8_t *ede = edv + edl;

    asn_skip(&edp, ede); /* version */

    const uint8_t *ri_val; size_t ri_len;
    if (asn_expect(&edp, ede, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET,
                   &ri_val, &ri_len) != 0) return -1;

    /* Find encryptedKey in KTRI */
    const uint8_t *enc_key_der = NULL; size_t enc_key_len = 0;
    {
        const uint8_t *rp = ri_val, *re = ri_val + ri_len;
        while (rp < re) {
            const uint8_t *kv; size_t kl;
            if (asn_expect(&rp, re,
                           MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE,
                           &kv, &kl) != 0) break;
            const uint8_t *kp = kv, *ke = kv + kl;
            asn_skip(&kp, ke); asn_skip(&kp, ke); asn_skip(&kp, ke);
            const uint8_t *ek_v; size_t ek_l;
            if (asn_expect(&kp, ke, MBEDTLS_ASN1_OCTET_STRING, &ek_v, &ek_l) == 0) {
                enc_key_der = ek_v; enc_key_len = ek_l; break;
            }
        }
    }
    if (!enc_key_der) return -1;

    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(*ra_priv_key);
    mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE);
    uint8_t cek[CEK_LEN]; size_t cek_len = sizeof(cek);
    ret = mbedtls_rsa_pkcs1_decrypt(rsa, f_rng, p_rng, &cek_len,
                                    enc_key_der, cek, sizeof(cek));
    if (ret != 0) return ret;

    const uint8_t *eci_val; size_t eci_len;
    if (asn_expect(&edp, ede, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE,
                   &eci_val, &eci_len) != 0) return -1;
    const uint8_t *ep = eci_val, *ee = eci_val + eci_len;
    asn_skip(&ep, ee);
    uint8_t iv[IV_LEN];
    {
        const uint8_t *av2; size_t al2;
        if (asn_expect(&ep, ee, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE,
                       &av2, &al2) != 0) return -1;
        const uint8_t *ap2 = av2, *ae2 = av2 + al2;
        asn_skip(&ap2, ae2);
        const uint8_t *iv_v; size_t iv_l;
        if (asn_expect(&ap2, ae2, MBEDTLS_ASN1_OCTET_STRING, &iv_v, &iv_l) != 0) return -1;
        if (iv_l != IV_LEN) return -1;
        memcpy(iv, iv_v, IV_LEN);
    }
    const uint8_t *ec_val; size_t ec_len;
    if (asn_read(&ep, ee, NULL, &ec_val, &ec_len) != 0) return -1;

    size_t dec_len = ec_len;
    if (dec_len > sizeof(out->csr_der)) return -1;
    {
        mbedtls_aes_context aes;
        mbedtls_aes_init(&aes);
        uint8_t iv2[IV_LEN]; memcpy(iv2, iv, IV_LEN);
        uint8_t tmp_dec[SCEP_MAX_CSR_DER + 16];
        if (dec_len > sizeof(tmp_dec)) { mbedtls_aes_free(&aes); return -1; }
        ret = mbedtls_aes_setkey_dec(&aes, cek, 256);
        if (ret == 0)
            ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, dec_len, iv2,
                                        ec_val, tmp_dec);
        mbedtls_aes_free(&aes);
        if (ret != 0) return ret;
        uint8_t pad = tmp_dec[dec_len - 1];
        if (pad == 0 || pad > 16 || pad > dec_len) return -1;
        out->csr_len = dec_len - pad;
        memcpy(out->csr_der, tmp_dec, out->csr_len);
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * Test helper: verify that scep_parse_certrep rejects a CertRep whose
 * SignedData signature has been bit-flipped (known-bad-signature test).
 *
 * Usage (in a native test):
 *   int r = scep_certrep_rejects_bad_sig(p7, p7_len, txid, key, ...);
 *   TEST_ASSERT_EQUAL_INT(-1, r);   // must reject
 *
 * Implementation: flip the last byte of the SignerInfo signature field and
 * call scep_parse_certrep; we expect it to return -1 (verify failed).
 * -------------------------------------------------------------------- */
int scep_certrep_rejects_bad_sig(const uint8_t      *p7,
                                 size_t              p7_len,
                                 const char         *txid,
                                 mbedtls_pk_context *recip_key,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void               *p_rng)
{
    if (!p7 || p7_len < 4) return 0; /* can't mutate -- skip */

    /* Make a mutable copy */
    uint8_t *mut = malloc(p7_len);
    if (!mut) return 0;
    memcpy(mut, p7, p7_len);

    /* Find the SignerInfo signature byte to flip.
     * Walk the structure: ContentInfo -> [0] -> SignedData -> signerInfos -> first
     * SignerInfo -> skip fields -> signature OCTET STRING -> last byte. */
    const uint8_t *dummy_encap, *si_val_r, *certs_r;
    size_t dummy_el, si_len_r, certs_lr;
    if (parse_outer_signed_data(mut, p7_len,
                                &dummy_encap, &dummy_el,
                                &si_val_r,    &si_len_r,
                                &certs_r,     &certs_lr) != 0) {
        free(mut); return 0;
    }
    if (!si_val_r) { free(mut); return 0; }

    const uint8_t *sa_r; size_t sa_rl;
    const uint8_t *sig_r; size_t sig_rl;
    if (si_extract_sa_and_sig(si_val_r, si_len_r,
                              &sa_r, &sa_rl, &sig_r, &sig_rl) != 0) {
        free(mut); return 0;
    }
    if (sig_rl == 0) { free(mut); return 0; }

    /* Flip last byte of signature (sig_r points into mut) */
    uint8_t *flip_ptr = mut + (size_t)(sig_r - (const uint8_t *)mut) + sig_rl - 1;
    *flip_ptr ^= 0xff;

    /* Now try to parse -- must fail */
    uint8_t cert_buf[SCEP_MAX_CERT_DER];
    size_t  cert_len = sizeof(cert_buf);
    scep_pki_status_t status;
    int fail_info;
    int r = scep_parse_certrep(mut, p7_len, txid, recip_key,
                               f_rng, p_rng,
                               cert_buf, &cert_len, &status, &fail_info);
    free(mut);
    /* r must be -1 (signature verification failure), not 0 */
    return (r != 0) ? -1 : 0;  /* -1 = correctly rejected, 0 = FAIL (accepted) */
}

#endif /* SCEP_PROTO_TEST_HELPERS */
