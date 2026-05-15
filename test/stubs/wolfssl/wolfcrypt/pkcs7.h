/*
 * Native test stub: wolfcrypt/pkcs7.h
 *
 * Provides just enough type and constant definitions to allow scep_proto.c
 * to compile on the native host.  No functions are implemented -- the PKCS#7
 * paths in scep_proto.c are guarded by SCEP_PROTO_NATIVE_STUBS and are not
 * called in native tests.
 *
 * Full PKCS#7 roundtrip tests run on-device via embedded/test_scep_proto.
 */
#pragma once
#include "wolfssl/wolfcrypt/settings.h"

#ifndef INVALID_DEVID
#define INVALID_DEVID (-2)
#endif

/* Tiny stub types -- enough for PKCS7Attrib array initialization in scep_proto.c */
typedef struct {
    const unsigned char *oid;
    unsigned int         oidSz;
    const unsigned char *value;
    unsigned int         valueSz;
} PKCS7Attrib;

/* Minimal wc_PKCS7 struct -- enough that the compiler accepts field access */
typedef struct wc_PKCS7 {
    void        *rng;
    unsigned char *content;
    unsigned int   contentSz;
    int            contentOID;
    int            hashOID;
    int            encryptOID;
    unsigned char *privateKey;
    unsigned int   privateKeySz;
    PKCS7Attrib  *signedAttribs;
    unsigned int   signedAttribsSz;
    unsigned char *singleCert;
    unsigned int   singleCertSz;
    /* cert array (MAX_PKCS7_CERTS=4) */
    unsigned char *cert[4];
    unsigned int   certSz[4];
    /* other fields accessed in scep_proto.c */
    int            keyWrapOID;
    int            keyAgreeOID;
} wc_PKCS7;

#define MAX_PKCS7_CERTS 4

/* All PKCS7 functions are stubs that abort -- never called in native tests */
#include <stdlib.h>
static inline int  wc_PKCS7_Init(wc_PKCS7 *p, void *heap, int devId)
    { (void)p;(void)heap;(void)devId; return 0; }
static inline int  wc_PKCS7_InitWithCert(wc_PKCS7 *p, unsigned char *d, unsigned int s)
    { (void)p;(void)d;(void)s; return 0; }
static inline void wc_PKCS7_Free(wc_PKCS7 *p) { (void)p; }
static inline void wc_PKCS7_AllowDegenerate(wc_PKCS7 *p, unsigned short f)
    { (void)p;(void)f; }
static inline int  wc_PKCS7_SetKey(wc_PKCS7 *p, unsigned char *k, unsigned int s)
    { (void)p;(void)k;(void)s; return 0; }
static inline int  wc_PKCS7_AddRecipient_KTRI(wc_PKCS7 *p, const unsigned char *c,
                                               unsigned int s, int o)
    { (void)p;(void)c;(void)s;(void)o; return 0; }
static inline int  wc_PKCS7_EncodeEnvelopedData(wc_PKCS7 *p, unsigned char *o, unsigned int s)
    { (void)p;(void)o;(void)s; abort(); return -1; }
static inline int  wc_PKCS7_EncodeSignedData(wc_PKCS7 *p, unsigned char *o, unsigned int s)
    { (void)p;(void)o;(void)s; abort(); return -1; }
static inline int  wc_PKCS7_VerifySignedData(wc_PKCS7 *p, unsigned char *m, unsigned int s)
    { (void)p;(void)m;(void)s; abort(); return -1; }
static inline int  wc_PKCS7_GetAttributeValue(wc_PKCS7 *p, const unsigned char *oid,
                                               unsigned int oidSz, unsigned char *out,
                                               unsigned int *outSz)
    { (void)p;(void)oid;(void)oidSz;(void)out;(void)outSz; return -1; }
static inline int  wc_PKCS7_DecodeEnvelopedData(wc_PKCS7 *p, unsigned char *msg,
                                                  unsigned int msgSz, unsigned char *out,
                                                  unsigned int outSz)
    { (void)p;(void)msg;(void)msgSz;(void)out;(void)outSz; abort(); return -1; }
static inline int  wc_PKCS7_AddCertificate(wc_PKCS7 *p, unsigned char *d, unsigned int s)
    { (void)p;(void)d;(void)s; return 0; }
