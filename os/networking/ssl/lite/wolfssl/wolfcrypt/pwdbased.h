/* pwdbased.h
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.  All rights reserved.
 *
 * This file is part of wolfSSL.
 *
 * Contact licensing@wolfssl.com with any questions or comments.
 *
 * http://www.wolfssl.com
 */



#ifndef NO_PWDBASED

#ifndef WOLF_CRYPT_PWDBASED_H
#define WOLF_CRYPT_PWDBASED_H

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/md5.h>       /* for hash type */
#include <wolfssl/wolfcrypt/sha.h>

#ifdef __cplusplus
    extern "C" {
#endif

/*
 * hashType renamed to typeH to avoid shadowing global declation here:
 * wolfssl/wolfcrypt/asn.h line 173 in enum Oid_Types
 */
WOLFSSL_API int wc_PBKDF1(byte* output, const byte* passwd, int pLen,
                      const byte* salt, int sLen, int iterations, int kLen,
                      int typeH);
WOLFSSL_API int wc_PBKDF2(byte* output, const byte* passwd, int pLen,
                      const byte* salt, int sLen, int iterations, int kLen,
                      int typeH);
WOLFSSL_API int wc_PKCS12_PBKDF(byte* output, const byte* passwd, int pLen,
                            const byte* salt, int sLen, int iterations,
                            int kLen, int typeH, int purpose);


#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLF_CRYPT_PWDBASED_H */
#endif /* NO_PWDBASED */
