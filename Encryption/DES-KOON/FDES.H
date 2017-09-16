/*
 * Copyright (c) 1990 David G. Koontz.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the above mentioned individual.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE
 */
/*
 *	fdes.h  - faster implementation of DES algorithm
 */

#define BIT(x)	( 1 << x )

#define AA 0
#define BB 1
#define RR 1
#define LL 0
#define SHIFT_FOR_ENCRYPT    1
#define SHIFT_FOR_DECRYPT   -1

/* How to find R Register Bits affecting S boxes:    */
/* this is an ENDIAN referenced byte index  */

#ifndef LITTLE_ENDIAN   /* BIG_ENDIAN */

#define S1   3
#define S2   7
#define S3   2
#define S4   6
#define S5   1
#define S6   5
#define S7   0
#define S8   4

#else			/* LITTLE_ENDIAN */

#define S1   0
#define S2   4
#define S3   1
#define S4   5
#define S5   2
#define S6   6
#define S7   3
#define S8   7

#endif

union LR_block {
	unsigned char string[8];
	unsigned long LR[2];
};
union block_48 {
	unsigned char string[8];
	unsigned long AB[2];
	unsigned short SxSy[4];
};


/* Key Schedule permuted for S Box input: */

static union block_48 K_S[16];
static union block_48 *key_start;
static int des_mode;

#include "ip.h"
#include "iip.h"
#include "key.h"
#include "s_p.h"
