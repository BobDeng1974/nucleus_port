/* ecc25519.h
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.  All rights reserved.
 *
 * This file is part of wolfSSL.
 *
 * Contact licensing@wolfssl.com with any questions or comments.
 *
 * http://www.wolfssl.com
 */

#ifndef WOLF_CRYPT_ECC25519_H
#define WOLF_CRYPT_ECC25519_H

#include <wolfssl/wolfcrypt/ecc25519_fe.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/random.h>

#ifdef HAVE_ECC25519

#ifdef __cplusplus
    extern "C" {
#endif

#define ECC25519_KEYSIZE 32

/* ECC set type */
typedef struct {
    int size;       /* The size of the curve in octets */
    const char* name;     /* name of this curve */
} ecc25519_set_type;


/* ECC point */
typedef struct {
    byte point[ECC25519_KEYSIZE];
}ECPoint;

/* An ECC25519 Key */
typedef struct {
    int type;           /* Public or Private */
    int idx;            /* Index into the ecc_sets[] for the parameters of
                           this curve if -1, this key is using user supplied
                           curve in dp */
    const ecc25519_set_type* dp;   /* domain parameters, either points to
                                   curves (idx >= 0) or user supplied */
    byte      f;        /* format of key */
    ECPoint   p;        /* public key  */
    ECPoint   k;        /* private key */
} ecc25519_key;

WOLFSSL_API
int wc_ecc25519_make_key(RNG* rng, int keysize, ecc25519_key* key);

WOLFSSL_API
int wc_ecc25519_shared_secret(ecc25519_key* private_key, ecc25519_key* public_key,
        byte* out, word32* outlen);

WOLFSSL_API
int wc_ecc25519_init(ecc25519_key* key);

WOLFSSL_API
void wc_ecc25519_free(ecc25519_key* key);


/* raw key helpers */
WOLFSSL_API
int wc_ecc25519_import_private_raw(const byte* priv, word32 privSz,
                              const byte* pub, word32 pubSz, ecc25519_key* key);
WOLFSSL_API
int wc_ecc25519_export_private_raw(ecc25519_key* key, byte* out, word32* outLen);

WOLFSSL_API
int wc_ecc25519_import_public(const byte* in, word32 inLen, ecc25519_key* key);

WOLFSSL_API
int wc_ecc25519_export_public(ecc25519_key* key, byte* out, word32* outLen);


/* size helper */
WOLFSSL_API
int wc_ecc25519_size(ecc25519_key* key);

#ifdef __cplusplus
    }    /* extern "C" */
#endif

#endif /* WOLF_CRYPT_ECC25519_H */
#endif /* HAVE_ECC25519 */

