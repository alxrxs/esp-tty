/*
 * Native test stub: wolfcrypt/asn_public.h
 *
 * Used only by test/native/test_scep_proto/ to reparse a DER CSR and verify
 * its subject CN + challengePassword attribute.  Backed by OpenSSL 3 X509_REQ.
 *
 * Previously also stubbed wc_InitDecodedCert / wc_ParseCert / wc_GetDateInfo
 * for lib/cred_store/, but cred_store now uses mbedtls_x509_crt directly and
 * those stubs were dead -- removed.
 */
#pragma once

#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/objects.h>
#include <string.h>
#include <stdint.h>

/* Match wolfSSL types so the test code reads naturally. */
#ifndef byte
typedef uint8_t  byte;
#endif
#ifndef word32
typedef uint32_t word32;
#endif
#ifndef BAD_FUNC_ARG
#define BAD_FUNC_ARG  (-173)
#endif

#define CTC_NAME_SIZE_SCEP 64

typedef struct {
    char subjectCN[CTC_NAME_SIZE_SCEP];
    char challengePw[CTC_NAME_SIZE_SCEP];
} ParsedCert;

static inline int scep_native_parse_csr(const byte *der, word32 derSz, ParsedCert *out)
{
    if (!der || !out) return BAD_FUNC_ARG;
    memset(out, 0, sizeof(*out));
    const unsigned char *p = der;
    X509_REQ *req = d2i_X509_REQ(NULL, &p, (long)derSz);
    if (!req) return -1;
    X509_NAME *name = X509_REQ_get_subject_name(req);
    if (name)
        X509_NAME_get_text_by_NID(name, NID_commonName,
                                  out->subjectCN, sizeof(out->subjectCN));
    int count = X509_REQ_get_attr_count(req);
    for (int i = 0; i < count; i++) {
        X509_ATTRIBUTE *attr = X509_REQ_get_attr(req, i);
        if (!attr) continue;
        ASN1_OBJECT *obj = X509_ATTRIBUTE_get0_object(attr);
        char oid_str[64];
        OBJ_obj2txt(oid_str, sizeof(oid_str), obj, 1);
        if (strcmp(oid_str, "1.2.840.113549.1.9.7") == 0) {
            ASN1_TYPE *val = X509_ATTRIBUTE_get0_type(attr, 0);
            if (val && val->value.asn1_string) {
                int vlen = val->value.asn1_string->length;
                if (vlen > 0 && vlen < (int)sizeof(out->challengePw)) {
                    memcpy(out->challengePw, val->value.asn1_string->data, vlen);
                }
            }
        }
    }
    X509_REQ_free(req);
    return 0;
}
