#ifndef __EC_VLONG_H
#define __EC_VLONG_H

#include <stdio.h>

#include "ec_param.h"

#ifndef USUAL_TYPES
	#define USUAL_TYPES
	typedef unsigned char	byte;
	typedef unsigned short	word16;
	typedef unsigned long	word32;
#endif /* ?USUAL_TYPES */

#define VL_UNITS ((GF_K*GF_L + 15)/16 + 1) /* must be large enough to hold a (packed) curve point (plus one element: the length) */

typedef word16 vlPoint [VL_UNITS + 2];


void vlPrint (FILE *out, const char *tag, const vlPoint k);
	/* printf prefix tag and the contents of k to file out */

void vlClear (vlPoint p);

void vlShortSet (vlPoint p, word16 u);
	/* sets p := u */

int  vlEqual (const vlPoint p, const vlPoint q);

int  vlGreater (const vlPoint p, const vlPoint q);

int  vlNumBits (const vlPoint k);
	/* evaluates to the number of bits of k (index of most significant bit, plus one) */

int  vlTakeBit (const vlPoint k, word16 i);
	/* evaluates to the i-th bit of k */

void vlRandom (vlPoint k);
	/* sets k := <random very long integer value> */

void vlCopy (vlPoint p, const vlPoint q);
	/* sets p := q */

void vlAdd (vlPoint u, const vlPoint v);

void vlSubtract (vlPoint u, const vlPoint v);

void vlRemainder (vlPoint u, const vlPoint v);

void vlMulMod (vlPoint u, const vlPoint v, const vlPoint w, const vlPoint m);

void vlShortLshift (vlPoint u, int n);

void vlShortRshift (vlPoint u, int n);

int  vlShortMultiply (vlPoint p, const vlPoint q, word16 d);
	/* sets p = q * d, where d is a single digit */

int  vlSelfTest (int test_count);

#endif /* __EC_VLONG_H */
