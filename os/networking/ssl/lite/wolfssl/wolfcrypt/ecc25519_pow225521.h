/* ecc25519_pow225521.h
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

fe_sq(t0,z); for (i = 1;i < 1;++i) fe_sq(t0,t0);
fe_sq(t1,t0); for (i = 1;i < 2;++i) fe_sq(t1,t1);
fe_mul(t1,z,t1);
fe_mul(t0,t0,t1);
fe_sq(t2,t0); for (i = 1;i < 1;++i) fe_sq(t2,t2);
fe_mul(t1,t1,t2);
fe_sq(t2,t1); for (i = 1;i < 5;++i) fe_sq(t2,t2);
fe_mul(t1,t2,t1);
fe_sq(t2,t1); for (i = 1;i < 10;++i) fe_sq(t2,t2);
fe_mul(t2,t2,t1);
fe_sq(t3,t2); for (i = 1;i < 20;++i) fe_sq(t3,t3);
fe_mul(t2,t3,t2);
fe_sq(t2,t2); for (i = 1;i < 10;++i) fe_sq(t2,t2);
fe_mul(t1,t2,t1);
fe_sq(t2,t1); for (i = 1;i < 50;++i) fe_sq(t2,t2);
fe_mul(t2,t2,t1);
fe_sq(t3,t2); for (i = 1;i < 100;++i) fe_sq(t3,t3);
fe_mul(t2,t3,t2);
fe_sq(t2,t2); for (i = 1;i < 50;++i) fe_sq(t2,t2);
fe_mul(t1,t2,t1);
fe_sq(t1,t1); for (i = 1;i < 5;++i) fe_sq(t1,t1);
fe_mul(out,t1,t0);

