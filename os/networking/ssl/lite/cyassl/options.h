/* cyassl options.h
 * generated from wolfssl/options.h
 */
/* wolfssl options.h
* generated from configure options
*
* Copyright (C) 2006-2015 wolfSSL Inc.
*
* This file is part of wolfSSL. (formerly known as CyaSSL)
*
*/

#ifndef CYASSL_OPTIONS_H
#define CYASSL_OPTIONS_H


#ifdef __cplusplus
extern "C" {
#endif

#undef  OPENSSL_EXTRA
#define OPENSSL_EXTRA

#undef  WOLFSSL_DTLS
#define WOLFSSL_DTLS

#ifndef WOLFSSL_OPTIONS_IGNORE_SYS
#undef  _POSIX_THREADS
#define _POSIX_THREADS
#endif

#undef  HAVE_THREAD_LS
#define HAVE_THREAD_LS

#ifndef WOLFSSL_OPTIONS_IGNORE_SYS
#undef  _THREAD_SAFE
#define _THREAD_SAFE
#endif

#undef  PERSIST_SESSION_CACHE
#define PERSIST_SESSION_CACHE

#undef  PERSIST_CERT_CACHE
#define PERSIST_CERT_CACHE

#undef  ATOMIC_USER
#define ATOMIC_USER

#undef  HAVE_PK_CALLBACKS
#define HAVE_PK_CALLBACKS

#undef  WOLFSSL_SNIFFER
#define WOLFSSL_SNIFFER

#undef  OPENSSL_EXTRA
#define OPENSSL_EXTRA

#undef  HAVE_AESGCM
#define HAVE_AESGCM

#undef  HAVE_AESCCM
#define HAVE_AESCCM

#undef  HAVE_CAMELLIA
#define HAVE_CAMELLIA

#undef  WOLFSSL_SHA512
#define WOLFSSL_SHA512

#undef  WOLFSSL_SHA384
#define WOLFSSL_SHA384

#undef  NO_DSA
#define NO_DSA

#undef  HAVE_ECC
#define HAVE_ECC

#undef  TFM_ECC256
#define TFM_ECC256

#undef  ECC_SHAMIR
#define ECC_SHAMIR

#undef  NO_RC4
#define NO_RC4

#undef  HAVE_HC128
#define HAVE_HC128

#undef  HAVE_RABBIT
#define HAVE_RABBIT

#undef  HAVE_POLY1305
#define HAVE_POLY1305

#undef  HAVE_ONE_TIME_AUTH
#define HAVE_ONE_TIME_AUTH

#undef  HAVE_CHACHA
#define HAVE_CHACHA

#undef  HAVE_HASHDRBG
#define HAVE_HASHDRBG

#undef  HAVE_OCSP
#define HAVE_OCSP

#undef  HAVE_OPENSSL_CMD
#define HAVE_OPENSSL_CMD

#undef  HAVE_CRL
#define HAVE_CRL

#undef  WOLFSSL_KEY_GEN
#define WOLFSSL_KEY_GEN

#undef  WOLFSSL_CERT_GEN
#define WOLFSSL_CERT_GEN

#undef  WOLFSSL_CERT_REQ
#define WOLFSSL_CERT_REQ

#undef  WOLFSSL_CERT_EXT
#define WOLFSSL_CERT_EXT

#undef  HAVE_PKCS7
#define HAVE_PKCS7

#undef  WOLFSSL_HAVE_WOLFSCEP
#define WOLFSSL_HAVE_WOLFSCEP

#undef  NO_MD4
#define NO_MD4

#undef  USE_FAST_MATH
#define USE_FAST_MATH

#undef  WOLFSSL_X86_64_BUILD
#define WOLFSSL_X86_64_BUILD

#undef  HAVE___UINT128_T
#define HAVE___UINT128_T


#ifdef __cplusplus
}
#endif


#endif /* CYASSL_OPTIONS_H */

