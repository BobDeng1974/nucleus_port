/* ecc25519_fe.h
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.  All rights reserved.
 *
 * This file is part of wolfSSL.
 *
 * Contact licensing@wolfssl.com with any questions or comments.
 *
 * http://www.wolfssl.com
 */


 /* Based On Daniel J Bernstein's curve25519 Public Domain ref10 work. */
#ifndef WOLF_CRYPT_ECC25519_FE_H
#define WOLF_CRYPT_ECC25519_FE_H

#include <wolfssl/wolfcrypt/settings.h>
#include <stdint.h>

#ifdef HAVE_ECC25519


typedef int32_t fe[10];

/*
fe means field element.
Here the field is \Z/(2^255-19).
An element t, entries t[0]...t[9], represents the integer
t[0]+2^26 t[1]+2^51 t[2]+2^77 t[3]+2^102 t[4]+...+2^230 t[9].
Bounds on each t[i] vary depending on context.
*/

void fe_frombytes(fe,const unsigned char *);
void fe_tobytes(unsigned char *,fe);

void fe_copy(fe,fe);
void fe_0(fe);
void fe_1(fe);
void fe_cswap(fe,fe,unsigned int);

void fe_add(fe,fe,fe);
void fe_sub(fe,fe,fe);
void fe_mul(fe,fe,fe);
void fe_sq(fe,fe);
void fe_mul121666(fe,fe);
void fe_invert(fe,fe);

#endif

#endif /*HAVE_ECC25519*/

