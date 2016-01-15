/* rsa.c
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.  All rights reserved.
 *
 * This file is part of wolfSSL.
 *
 * Contact licensing@wolfssl.com with any questions or comments.
 *
 * http://www.wolfssl.com
 */


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifndef NO_RSA

#include <wolfssl/wolfcrypt/rsa.h>

#ifdef HAVE_FIPS
int  wc_InitRsaKey(RsaKey* key, void* ptr)
{
    return InitRsaKey_fips(key, ptr);
}


int  wc_FreeRsaKey(RsaKey* key)
{
    return FreeRsaKey_fips(key);
}


int  wc_RsaPublicEncrypt(const byte* in, word32 inLen, byte* out,
                                 word32 outLen, RsaKey* key, RNG* rng)
{
    return RsaPublicEncrypt_fips(in, inLen, out, outLen, key, rng);
}


int  wc_RsaPrivateDecryptInline(byte* in, word32 inLen, byte** out,
                                        RsaKey* key)
{
    return RsaPrivateDecryptInline_fips(in, inLen, out, key);
}


int  wc_RsaPrivateDecrypt(const byte* in, word32 inLen, byte* out,
                                  word32 outLen, RsaKey* key)
{
    return RsaPrivateDecrypt_fips(in, inLen, out, outLen, key);
}


int  wc_RsaSSL_Sign(const byte* in, word32 inLen, byte* out,
                            word32 outLen, RsaKey* key, RNG* rng)
{
    return RsaSSL_Sign_fips(in, inLen, out, outLen, key, rng);
}


int  wc_RsaSSL_VerifyInline(byte* in, word32 inLen, byte** out, RsaKey* key)
{
    return RsaSSL_VerifyInline_fips(in, inLen, out, key);
}


int  wc_RsaSSL_Verify(const byte* in, word32 inLen, byte* out,
                              word32 outLen, RsaKey* key)
{
    return RsaSSL_Verify_fips(in, inLen, out, outLen, key);
}


int  wc_RsaEncryptSize(RsaKey* key)
{
    return RsaEncryptSize_fips(key);
}


int wc_RsaFlattenPublicKey(RsaKey* key, byte* a, word32* aSz, byte* b,
                           word32* bSz)
{
    /* not specified as fips so not needing _fips */
    return RsaFlattenPublicKey(key, a, aSz, b, bSz);
}
#ifdef WOLFSSL_KEY_GEN
    int wc_MakeRsaKey(RsaKey* key, int size, long e, RNG* rng)
    {
        return MakeRsaKey(key, size, e, rng);
    }
#endif


#ifdef HAVE_CAVIUM
    int  wc_RsaInitCavium(RsaKey* key, int i)
    {
        return RsaInitCavium(key, i);
    }


    void wc_RsaFreeCavium(RsaKey* key)
    {
        RsaFreeCavium(key);
    }
#endif

/* these are functions in asn and are routed to wolfssl/wolfcrypt/asn.c
* wc_RsaPrivateKeyDecode
* wc_RsaPublicKeyDecode
*/

#else /* else build without fips */
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #include <wolfcrypt/src/misc.c>
#endif

#ifdef SHOW_GEN
    #ifdef FREESCALE_MQX
        #include <fio.h>
    #else
        #include <stdio.h>
    #endif
#endif

#ifdef HAVE_CAVIUM
    static int  InitCaviumRsaKey(RsaKey* key, void* heap);
    static int  FreeCaviumRsaKey(RsaKey* key);
    static int  CaviumRsaPublicEncrypt(const byte* in, word32 inLen, byte* out,
                                       word32 outLen, RsaKey* key);
    static int  CaviumRsaPrivateDecrypt(const byte* in, word32 inLen, byte* out,
                                        word32 outLen, RsaKey* key);
    static int  CaviumRsaSSL_Sign(const byte* in, word32 inLen, byte* out,
                                  word32 outLen, RsaKey* key);
    static int  CaviumRsaSSL_Verify(const byte* in, word32 inLen, byte* out,
                                    word32 outLen, RsaKey* key);
#endif

enum {
    RSA_PUBLIC_ENCRYPT  = 0,
    RSA_PUBLIC_DECRYPT  = 1,
    RSA_PRIVATE_ENCRYPT = 2,
    RSA_PRIVATE_DECRYPT = 3,

    RSA_BLOCK_TYPE_1 = 1,
    RSA_BLOCK_TYPE_2 = 2,

    RSA_MIN_SIZE = 512,
    RSA_MAX_SIZE = 4096,

    RSA_MIN_PAD_SZ   = 11      /* seperator + 0 + pad value + 8 pads */
};


int wc_InitRsaKey(RsaKey* key, void* heap)
{
#ifdef HAVE_CAVIUM
    if (key->magic == WOLFSSL_RSA_CAVIUM_MAGIC)
        return InitCaviumRsaKey(key, heap);
#endif

    key->type = -1;  /* haven't decided yet */
    key->heap = heap;

/* TomsFastMath doesn't use memory allocation */
#ifndef USE_FAST_MATH
    key->n.dp = key->e.dp = 0;  /* public  alloc parts */

    key->d.dp = key->p.dp  = 0;  /* private alloc parts */
    key->q.dp = key->dP.dp = 0;  
    key->u.dp = key->dQ.dp = 0;
#else
    mp_init(&key->n);
    mp_init(&key->e);
    mp_init(&key->d);
    mp_init(&key->p);
    mp_init(&key->q);
    mp_init(&key->dP);
    mp_init(&key->dQ);
    mp_init(&key->u);
#endif

    return 0;
}


int wc_FreeRsaKey(RsaKey* key)
{
    (void)key;

#ifdef HAVE_CAVIUM
    if (key->magic == WOLFSSL_RSA_CAVIUM_MAGIC)
        return FreeCaviumRsaKey(key);
#endif

/* TomsFastMath doesn't use memory allocation */
#ifndef USE_FAST_MATH
    if (key->type == RSA_PRIVATE) {
        mp_clear(&key->u);
        mp_clear(&key->dQ);
        mp_clear(&key->dP);
        mp_clear(&key->q);
        mp_clear(&key->p);
        mp_clear(&key->d);
    }
    mp_clear(&key->e);
    mp_clear(&key->n);
#endif

    return 0;
}

static int wc_RsaPad(const byte* input, word32 inputLen, byte* pkcsBlock,
                   word32 pkcsBlockLen, byte padValue, RNG* rng)
{
    if (inputLen == 0)
        return 0;

    pkcsBlock[0] = 0x0;       /* set first byte to zero and advance */
    pkcsBlock++; pkcsBlockLen--;
    pkcsBlock[0] = padValue;  /* insert padValue */

    if (padValue == RSA_BLOCK_TYPE_1)
        /* pad with 0xff bytes */
        XMEMSET(&pkcsBlock[1], 0xFF, pkcsBlockLen - inputLen - 2);
    else {
        /* pad with non-zero random bytes */
        word32 padLen = pkcsBlockLen - inputLen - 1, i;
        int    ret    = wc_RNG_GenerateBlock(rng, &pkcsBlock[1], padLen);

        if (ret != 0)
            return ret;

        /* remove zeros */
        for (i = 1; i < padLen; i++)
            if (pkcsBlock[i] == 0) pkcsBlock[i] = 0x01;
    }

    pkcsBlock[pkcsBlockLen-inputLen-1] = 0;     /* separator */
    XMEMCPY(pkcsBlock+pkcsBlockLen-inputLen, input, inputLen);

    return 0;
}


/* UnPad plaintext, set start to *output, return length of plaintext,
 * < 0 on error */
static int RsaUnPad(const byte *pkcsBlock, unsigned int pkcsBlockLen,
                       byte **output, byte padValue)
{
    word32 maxOutputLen = (pkcsBlockLen > 10) ? (pkcsBlockLen - 10) : 0,
           invalid = 0,
           i = 1,
           outputLen;

    if (pkcsBlock[0] != 0x0) /* skip past zero */
        invalid = 1;
    pkcsBlock++; pkcsBlockLen--;

    /* Require block type padValue */
    invalid = (pkcsBlock[0] != padValue) || invalid;

    /* verify the padding until we find the separator */
    if (padValue == RSA_BLOCK_TYPE_1) {
        while (i<pkcsBlockLen && pkcsBlock[i++] == 0xFF) {/* Null body */}
    }
    else {
        while (i<pkcsBlockLen && pkcsBlock[i++]) {/* Null body */}
    }

    if(!(i==pkcsBlockLen || pkcsBlock[i-1]==0)) {
        WOLFSSL_MSG("RsaUnPad error, bad formatting");
        return RSA_PAD_E;
    }

    outputLen = pkcsBlockLen - i;
    invalid = (outputLen > maxOutputLen) || invalid;

    if (invalid) {
        WOLFSSL_MSG("RsaUnPad error, bad formatting");
        return RSA_PAD_E;
    }

    *output = (byte *)(pkcsBlock + i);
    return outputLen;
}


static int wc_RsaFunction(const byte* in, word32 inLen, byte* out, word32* outLen,
                       int type, RsaKey* key)
{
    #define ERROR_OUT(x) { ret = (x); goto done;}

    mp_int tmp;
    int    ret = 0;
    word32 keyLen, len;

    if (mp_init(&tmp) != MP_OKAY)
        return MP_INIT_E;

    if (mp_read_unsigned_bin(&tmp, (byte*)in, inLen) != MP_OKAY)
        ERROR_OUT(MP_READ_E);

    if (type == RSA_PRIVATE_DECRYPT || type == RSA_PRIVATE_ENCRYPT) {
        #ifdef RSA_LOW_MEM      /* half as much memory but twice as slow */
            if (mp_exptmod(&tmp, &key->d, &key->n, &tmp) != MP_OKAY)
                ERROR_OUT(MP_EXPTMOD_E);
        #else
            #define INNER_ERROR_OUT(x) { ret = (x); goto inner_done; }

            mp_int tmpa, tmpb;

            if (mp_init(&tmpa) != MP_OKAY)
                ERROR_OUT(MP_INIT_E);

            if (mp_init(&tmpb) != MP_OKAY) {
                mp_clear(&tmpa);
                ERROR_OUT(MP_INIT_E);
            }

            /* tmpa = tmp^dP mod p */
            if (mp_exptmod(&tmp, &key->dP, &key->p, &tmpa) != MP_OKAY)
                INNER_ERROR_OUT(MP_EXPTMOD_E);

            /* tmpb = tmp^dQ mod q */
            if (mp_exptmod(&tmp, &key->dQ, &key->q, &tmpb) != MP_OKAY)
                INNER_ERROR_OUT(MP_EXPTMOD_E);

            /* tmp = (tmpa - tmpb) * qInv (mod p) */
            if (mp_sub(&tmpa, &tmpb, &tmp) != MP_OKAY)
                INNER_ERROR_OUT(MP_SUB_E);

            if (mp_mulmod(&tmp, &key->u, &key->p, &tmp) != MP_OKAY)
                INNER_ERROR_OUT(MP_MULMOD_E);

            /* tmp = tmpb + q * tmp */
            if (mp_mul(&tmp, &key->q, &tmp) != MP_OKAY)
                INNER_ERROR_OUT(MP_MUL_E);

            if (mp_add(&tmp, &tmpb, &tmp) != MP_OKAY)
                INNER_ERROR_OUT(MP_ADD_E);

        inner_done:
            mp_clear(&tmpa);
            mp_clear(&tmpb);

            if (ret != 0) return ret;

        #endif   /* RSA_LOW_MEM */
    }
    else if (type == RSA_PUBLIC_ENCRYPT || type == RSA_PUBLIC_DECRYPT) {
        if (mp_exptmod(&tmp, &key->e, &key->n, &tmp) != MP_OKAY)
            ERROR_OUT(MP_EXPTMOD_E);
    }
    else
        ERROR_OUT(RSA_WRONG_TYPE_E);

    keyLen = mp_unsigned_bin_size(&key->n);
    if (keyLen > *outLen)
        ERROR_OUT(RSA_BUFFER_E);

    len = mp_unsigned_bin_size(&tmp);

    /* pad front w/ zeros to match key length */
    while (len < keyLen) {
        *out++ = 0x00;
        len++;
    }

    *outLen = keyLen;

    /* convert */
    if (mp_to_unsigned_bin(&tmp, out) != MP_OKAY)
        ERROR_OUT(MP_TO_E);
   
done: 
    mp_clear(&tmp);
    return ret;
}


int wc_RsaPublicEncrypt(const byte* in, word32 inLen, byte* out, word32 outLen,
                     RsaKey* key, RNG* rng)
{
    int sz, ret;

#ifdef HAVE_CAVIUM
    if (key->magic == WOLFSSL_RSA_CAVIUM_MAGIC)
        return CaviumRsaPublicEncrypt(in, inLen, out, outLen, key);
#endif

    sz = mp_unsigned_bin_size(&key->n);
    if (sz > (int)outLen)
        return RSA_BUFFER_E;

    if (inLen > (word32)(sz - RSA_MIN_PAD_SZ))
        return RSA_BUFFER_E;

    ret = wc_RsaPad(in, inLen, out, sz, RSA_BLOCK_TYPE_2, rng);
    if (ret != 0)
        return ret;

    if ((ret = wc_RsaFunction(out, sz, out, &outLen, RSA_PUBLIC_ENCRYPT, key)) < 0)
        sz = ret;

    return sz;
}


int wc_RsaPrivateDecryptInline(byte* in, word32 inLen, byte** out, RsaKey* key)
{
    int ret;

#ifdef HAVE_CAVIUM
    if (key->magic == WOLFSSL_RSA_CAVIUM_MAGIC) {
        ret = CaviumRsaPrivateDecrypt(in, inLen, in, inLen, key);
        if (ret > 0)
            *out = in;
        return ret;
    }
#endif

    if ((ret = wc_RsaFunction(in, inLen, in, &inLen, RSA_PRIVATE_DECRYPT, key))
            < 0) {
        return ret;
    }
 
    return RsaUnPad(in, inLen, out, RSA_BLOCK_TYPE_2);
}


int wc_RsaPrivateDecrypt(const byte* in, word32 inLen, byte* out, word32 outLen,
                     RsaKey* key)
{
    int plainLen;
    byte*  tmp;
    byte*  pad = 0;

#ifdef HAVE_CAVIUM
    if (key->magic == WOLFSSL_RSA_CAVIUM_MAGIC)
        return CaviumRsaPrivateDecrypt(in, inLen, out, outLen, key);
#endif

    tmp = (byte*)XMALLOC(inLen, key->heap, DYNAMIC_TYPE_RSA);
    if (tmp == NULL) {
        return MEMORY_E;
    }

    XMEMCPY(tmp, in, inLen);

    if ( (plainLen = wc_RsaPrivateDecryptInline(tmp, inLen, &pad, key) ) < 0) {
        XFREE(tmp, key->heap, DYNAMIC_TYPE_RSA);
        return plainLen;
    }
    if (plainLen > (int)outLen)
        plainLen = BAD_FUNC_ARG;
    else
        XMEMCPY(out, pad, plainLen);

    ForceZero(tmp, inLen);
    XFREE(tmp, key->heap, DYNAMIC_TYPE_RSA);

    return plainLen;
}


/* for Rsa Verify */
int wc_RsaSSL_VerifyInline(byte* in, word32 inLen, byte** out, RsaKey* key)
{
    int ret;

#ifdef HAVE_CAVIUM
    if (key->magic == WOLFSSL_RSA_CAVIUM_MAGIC) {
        ret = CaviumRsaSSL_Verify(in, inLen, in, inLen, key);
        if (ret > 0)
            *out = in;
        return ret;
    }
#endif

    if ((ret = wc_RsaFunction(in, inLen, in, &inLen, RSA_PUBLIC_DECRYPT, key))
            < 0) {
        return ret;
    }
  
    return RsaUnPad(in, inLen, out, RSA_BLOCK_TYPE_1);
}


int wc_RsaSSL_Verify(const byte* in, word32 inLen, byte* out, word32 outLen,
                     RsaKey* key)
{
    int plainLen;
    byte*  tmp;
    byte*  pad = 0;

#ifdef HAVE_CAVIUM
    if (key->magic == WOLFSSL_RSA_CAVIUM_MAGIC)
        return CaviumRsaSSL_Verify(in, inLen, out, outLen, key);
#endif

    tmp = (byte*)XMALLOC(inLen, key->heap, DYNAMIC_TYPE_RSA);
    if (tmp == NULL) {
        return MEMORY_E;
    }

    XMEMCPY(tmp, in, inLen);

    if ( (plainLen = wc_RsaSSL_VerifyInline(tmp, inLen, &pad, key) ) < 0) {
        XFREE(tmp, key->heap, DYNAMIC_TYPE_RSA);
        return plainLen;
    }

    if (plainLen > (int)outLen)
        plainLen = BAD_FUNC_ARG;
    else
        XMEMCPY(out, pad, plainLen);

    ForceZero(tmp, inLen);
    XFREE(tmp, key->heap, DYNAMIC_TYPE_RSA);

    return plainLen;
}


/* for Rsa Sign */
int wc_RsaSSL_Sign(const byte* in, word32 inLen, byte* out, word32 outLen,
                      RsaKey* key, RNG* rng)
{
    int sz, ret;

#ifdef HAVE_CAVIUM
    if (key->magic == WOLFSSL_RSA_CAVIUM_MAGIC)
        return CaviumRsaSSL_Sign(in, inLen, out, outLen, key);
#endif

    sz = mp_unsigned_bin_size(&key->n);
    if (sz > (int)outLen)
        return RSA_BUFFER_E;

    if (inLen > (word32)(sz - RSA_MIN_PAD_SZ))
        return RSA_BUFFER_E;

    ret = wc_RsaPad(in, inLen, out, sz, RSA_BLOCK_TYPE_1, rng);
    if (ret != 0)
        return ret;

    if ((ret = wc_RsaFunction(out, sz, out, &outLen, RSA_PRIVATE_ENCRYPT,key)) < 0)
        sz = ret;
    
    return sz;
}


int wc_RsaEncryptSize(RsaKey* key)
{
#ifdef HAVE_CAVIUM
    if (key->magic == WOLFSSL_RSA_CAVIUM_MAGIC)
        return key->c_nSz;
#endif
    return mp_unsigned_bin_size(&key->n);
}


int wc_RsaFlattenPublicKey(RsaKey* key, byte* e, word32* eSz, byte* n, word32* nSz)
{
    int sz, ret;

    if (key == NULL || e == NULL || eSz == NULL || n == NULL || nSz == NULL)
       return BAD_FUNC_ARG;

    sz = mp_unsigned_bin_size(&key->e);
    if ((word32)sz > *nSz)
        return RSA_BUFFER_E;
    ret = mp_to_unsigned_bin(&key->e, e);
    if (ret != MP_OKAY)
        return ret;
    *eSz = (word32)sz;

    sz = mp_unsigned_bin_size(&key->n);
    if ((word32)sz > *nSz)
        return RSA_BUFFER_E;
    ret = mp_to_unsigned_bin(&key->n, n);
    if (ret != MP_OKAY)
        return ret;
    *nSz = (word32)sz;

    return 0;
}


#ifdef WOLFSSL_KEY_GEN

static const int USE_BBS = 1;

static int rand_prime(mp_int* N, int len, RNG* rng, void* heap)
{
    int   err, res, type;
    byte* buf;

    (void)heap;
    if (N == NULL || rng == NULL)
       return BAD_FUNC_ARG; 

    /* get type */
    if (len < 0) {
        type = USE_BBS;
        len = -len;
    } else {
        type = 0;
    }

    /* allow sizes between 2 and 512 bytes for a prime size */
    if (len < 2 || len > 512) { 
        return BAD_FUNC_ARG;
    }
   
    /* allocate buffer to work with */
    buf = (byte*)XMALLOC(len, heap, DYNAMIC_TYPE_RSA);
    if (buf == NULL) {
        return MEMORY_E;
    }
    XMEMSET(buf, 0, len);

    do {
#ifdef SHOW_GEN
        printf(".");
        fflush(stdout);
#endif
        /* generate value */
        err = wc_RNG_GenerateBlock(rng, buf, len);
        if (err != 0) {
            XFREE(buf, heap, DYNAMIC_TYPE_RSA);
            return err;
        }

        /* munge bits */
        buf[0]     |= 0x80 | 0x40;
        buf[len-1] |= 0x01 | ((type & USE_BBS) ? 0x02 : 0x00);
 
        /* load value */
        if ((err = mp_read_unsigned_bin(N, buf, len)) != MP_OKAY) {
            XFREE(buf, heap, DYNAMIC_TYPE_RSA);
            return err;
        }

        /* test */
        if ((err = mp_prime_is_prime(N, 8, &res)) != MP_OKAY) {
            XFREE(buf, heap, DYNAMIC_TYPE_RSA);
            return err;
        }
    } while (res == MP_NO);

    ForceZero(buf, len);
    XFREE(buf, heap, DYNAMIC_TYPE_RSA);

    return 0;
}


/* Make an RSA key for size bits, with e specified, 65537 is a good e */
int wc_MakeRsaKey(RsaKey* key, int size, long e, RNG* rng)
{
    mp_int p, q, tmp1, tmp2, tmp3;
    int    err;

    if (key == NULL || rng == NULL)
        return BAD_FUNC_ARG;

    if (size < RSA_MIN_SIZE || size > RSA_MAX_SIZE)
        return BAD_FUNC_ARG;

    if (e < 3 || (e & 1) == 0)
        return BAD_FUNC_ARG;

    if ((err = mp_init_multi(&p, &q, &tmp1, &tmp2, &tmp3, NULL)) != MP_OKAY)
        return err;

    err = mp_set_int(&tmp3, e);

    /* make p */
    if (err == MP_OKAY) {
        do {
            err = rand_prime(&p, size/16, rng, key->heap); /* size in bytes/2 */

            if (err == MP_OKAY)
                err = mp_sub_d(&p, 1, &tmp1);  /* tmp1 = p-1 */

            if (err == MP_OKAY)
                err = mp_gcd(&tmp1, &tmp3, &tmp2);  /* tmp2 = gcd(p-1, e) */
        } while (err == MP_OKAY && mp_cmp_d(&tmp2, 1) != 0);  /* e divdes p-1 */
    }

    /* make q */
    if (err == MP_OKAY) {
        do {
            err = rand_prime(&q, size/16, rng, key->heap); /* size in bytes/2 */

            if (err == MP_OKAY)
                err = mp_sub_d(&q, 1, &tmp1);  /* tmp1 = q-1 */

            if (err == MP_OKAY)
                err = mp_gcd(&tmp1, &tmp3, &tmp2);  /* tmp2 = gcd(q-1, e) */
        } while (err == MP_OKAY && mp_cmp_d(&tmp2, 1) != 0);  /* e divdes q-1 */
    }

    if (err == MP_OKAY)
        err = mp_init_multi(&key->n, &key->e, &key->d, &key->p, &key->q, NULL);

    if (err == MP_OKAY)
        err = mp_init_multi(&key->dP, &key->dQ, &key->u, NULL, NULL, NULL);

    if (err == MP_OKAY)
        err = mp_sub_d(&p, 1, &tmp2);  /* tmp2 = p-1 */

    if (err == MP_OKAY)
        err = mp_lcm(&tmp1, &tmp2, &tmp1);  /* tmp1 = lcm(p-1, q-1),last loop */

    /* make key */
    if (err == MP_OKAY)
        err = mp_set_int(&key->e, e);  /* key->e = e */

    if (err == MP_OKAY)                /* key->d = 1/e mod lcm(p-1, q-1) */
        err = mp_invmod(&key->e, &tmp1, &key->d);

    if (err == MP_OKAY)
        err = mp_mul(&p, &q, &key->n);  /* key->n = pq */

    if (err == MP_OKAY)
        err = mp_sub_d(&p, 1, &tmp1);

    if (err == MP_OKAY)
        err = mp_sub_d(&q, 1, &tmp2);

    if (err == MP_OKAY)
        err = mp_mod(&key->d, &tmp1, &key->dP);

    if (err == MP_OKAY)
        err = mp_mod(&key->d, &tmp2, &key->dQ);

    if (err == MP_OKAY)
        err = mp_invmod(&q, &p, &key->u);

    if (err == MP_OKAY)
        err = mp_copy(&p, &key->p);

    if (err == MP_OKAY)
        err = mp_copy(&q, &key->q);

    if (err == MP_OKAY)
        key->type = RSA_PRIVATE; 

    mp_clear(&tmp3); 
    mp_clear(&tmp2); 
    mp_clear(&tmp1); 
    mp_clear(&q); 
    mp_clear(&p);

    if (err != MP_OKAY) {
        wc_FreeRsaKey(key);        
        return err;
    }

    return 0;
}


#endif /* WOLFSSL_KEY_GEN */


#ifdef HAVE_CAVIUM

#include <cyassl/ctaocrypt/logging.h>
#include "cavium_common.h"

/* Initiliaze RSA for use with Nitrox device */
int RsaInitCavium(RsaKey* rsa, int devId)
{
    if (rsa == NULL)
        return -1;

    if (CspAllocContext(CONTEXT_SSL, &rsa->contextHandle, devId) != 0)
        return -1;

    rsa->devId = devId;
    rsa->magic = WOLFSSL_RSA_CAVIUM_MAGIC;
   
    return 0;
}


/* Free RSA from use with Nitrox device */
void wc_RsaFreeCavium(RsaKey* rsa)
{
    if (rsa == NULL)
        return;

    CspFreeContext(CONTEXT_SSL, rsa->contextHandle, rsa->devId);
    rsa->magic = 0;
}


/* Initialize cavium RSA key */
static int InitCaviumRsaKey(RsaKey* key, void* heap)
{
    if (key == NULL)
        return BAD_FUNC_ARG;

    key->heap = heap;
    key->type = -1;   /* don't know yet */

    key->c_n  = NULL;
    key->c_e  = NULL;
    key->c_d  = NULL;
    key->c_p  = NULL;
    key->c_q  = NULL;
    key->c_dP = NULL;
    key->c_dQ = NULL;
    key->c_u  = NULL;

    key->c_nSz   = 0;
    key->c_eSz   = 0;
    key->c_dSz   = 0;
    key->c_pSz   = 0;
    key->c_qSz   = 0;
    key->c_dP_Sz = 0;
    key->c_dQ_Sz = 0;
    key->c_uSz   = 0;
    
    return 0;
}


/* Free cavium RSA key */
static int FreeCaviumRsaKey(RsaKey* key)
{
    if (key == NULL)
        return BAD_FUNC_ARG;

    XFREE(key->c_n,  key->heap, DYNAMIC_TYPE_CAVIUM_TMP);
    XFREE(key->c_e,  key->heap, DYNAMIC_TYPE_CAVIUM_TMP);
    XFREE(key->c_d,  key->heap, DYNAMIC_TYPE_CAVIUM_TMP);
    XFREE(key->c_p,  key->heap, DYNAMIC_TYPE_CAVIUM_TMP);
    XFREE(key->c_q,  key->heap, DYNAMIC_TYPE_CAVIUM_TMP);
    XFREE(key->c_dP, key->heap, DYNAMIC_TYPE_CAVIUM_TMP);
    XFREE(key->c_dQ, key->heap, DYNAMIC_TYPE_CAVIUM_TMP);
    XFREE(key->c_u,  key->heap, DYNAMIC_TYPE_CAVIUM_TMP);

    return InitCaviumRsaKey(key, key->heap);  /* reset pointers */
}


static int CaviumRsaPublicEncrypt(const byte* in, word32 inLen, byte* out,
                                   word32 outLen, RsaKey* key)
{
    word32 requestId;
    word32 ret;

    if (key == NULL || in == NULL || out == NULL || outLen < (word32)key->c_nSz)
        return -1;

    ret = CspPkcs1v15Enc(CAVIUM_BLOCKING, BT2, key->c_nSz, key->c_eSz,
                         (word16)inLen, key->c_n, key->c_e, (byte*)in, out,
                         &requestId, key->devId);
    if (ret != 0) {
        WOLFSSL_MSG("Cavium Enc BT2 failed");
        return -1;
    }
    return key->c_nSz;
}


static INLINE void ato16(const byte* c, word16* u16)
{
    *u16 = (c[0] << 8) | (c[1]);
}


static int CaviumRsaPrivateDecrypt(const byte* in, word32 inLen, byte* out,
                                    word32 outLen, RsaKey* key)
{
    word32 requestId;
    word32 ret;
    word16 outSz = (word16)outLen;

    if (key == NULL || in == NULL || out == NULL || inLen != (word32)key->c_nSz)
        return -1;

    ret = CspPkcs1v15CrtDec(CAVIUM_BLOCKING, BT2, key->c_nSz, key->c_q,
                            key->c_dQ, key->c_p, key->c_dP, key->c_u,
                            (byte*)in, &outSz, out, &requestId, key->devId);
    if (ret != 0) {
        WOLFSSL_MSG("Cavium CRT Dec BT2 failed");
        return -1;
    }
    ato16((const byte*)&outSz, &outSz); 

    return outSz;
}


static int CaviumRsaSSL_Sign(const byte* in, word32 inLen, byte* out,
                             word32 outLen, RsaKey* key)
{
    word32 requestId;
    word32 ret;

    if (key == NULL || in == NULL || out == NULL || inLen == 0 || outLen <
                                                             (word32)key->c_nSz)
        return -1;

    ret = CspPkcs1v15CrtEnc(CAVIUM_BLOCKING, BT1, key->c_nSz, (word16)inLen,
                            key->c_q, key->c_dQ, key->c_p, key->c_dP, key->c_u,
                            (byte*)in, out, &requestId, key->devId);
    if (ret != 0) {
        WOLFSSL_MSG("Cavium CRT Enc BT1 failed");
        return -1;
    }
    return key->c_nSz;
}


static int CaviumRsaSSL_Verify(const byte* in, word32 inLen, byte* out,
                               word32 outLen, RsaKey* key)
{
    word32 requestId;
    word32 ret;
    word16 outSz = (word16)outLen;

    if (key == NULL || in == NULL || out == NULL || inLen != (word32)key->c_nSz)
        return -1;

    ret = CspPkcs1v15Dec(CAVIUM_BLOCKING, BT1, key->c_nSz, key->c_eSz,
                         key->c_n, key->c_e, (byte*)in, &outSz, out,
                         &requestId, key->devId);
    if (ret != 0) {
        WOLFSSL_MSG("Cavium Dec BT1 failed");
        return -1;
    }
    outSz = ntohs(outSz);

    return outSz;
}


#endif /* HAVE_CAVIUM */

#endif /* HAVE_FIPS */
#endif /* NO_RSA */

