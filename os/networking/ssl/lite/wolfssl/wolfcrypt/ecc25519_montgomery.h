/* ecc25519_montgomery.h
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

fe_sub(tmp0,x3,z3);
fe_sub(tmp1,x2,z2);
fe_add(x2,x2,z2);
fe_add(z2,x3,z3);
fe_mul(z3,tmp0,x2);
fe_mul(z2,z2,tmp1);
fe_sq(tmp0,tmp1);
fe_sq(tmp1,x2);
fe_add(x3,z3,z2);
fe_sub(z2,z3,z2);
fe_mul(x2,tmp1,tmp0);
fe_sub(tmp1,tmp1,tmp0);
fe_sq(z2,z2);
fe_mul121666(z3,tmp1);
fe_sq(x3,x3);
fe_add(tmp0,tmp0,z3);
fe_mul(z3,x1,z2);
fe_mul(z2,tmp1,tmp0);

