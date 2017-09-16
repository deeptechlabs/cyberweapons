/*
 *	Data Encryption Standard (DES) Layer
 *	D.P.Mitchell  83/06/08.
 */

#include "crypt.h"

extern long s0p[],s1p[],s2p[],s3p[],s4p[],s5p[],s6p[],s7p[];
extern int subkeys[];

des(block)
Block *block;
{
	register long crypto, temp;
	register int *key;
	register round;
	register long right, left;

	left = block->left;
	right = block->right;
	key = subkeys;
	for (round = 0; round < 16; round++) {
		temp = (right << 1) | ((right >> 31) & 1);
		crypto  = s0p[(temp & 0x3f) ^ *key++];
		crypto |= s1p[((temp & 0x3f0) >> 4) ^ *key++];
		crypto |= s2p[((temp & 0x3f00) >> 8) ^ *key++];
		crypto |= s3p[((temp & 0x3f000) >> 12) ^ *key++];
		crypto |= s4p[((temp & 0x3f0000) >> 16) ^ *key++];
		crypto |= s5p[((temp & 0x3f00000) >> 20) ^ *key++];
		crypto |= s6p[((temp & 0x3f000000) >> 24) ^ *key++];
		temp = ((right & 1) << 5) | ((right >> 27) & 0x1f);
		crypto |= s7p[temp ^ *key++];
		if (round == 15)
			left ^= crypto;
		else {
			temp = left;
			left = right;
			right = temp ^ crypto;
		}
	}
	block->left = left;
	block->right = right;
}
