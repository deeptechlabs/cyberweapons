/*
 *	Generate Key-dependent Permutation of 128 Characters
 *	D.P.Mitchell  83/06/28.
 */

#include "crypt.h"

extern Block xkey[];
Block tempkey[SUPERSIZE];

int permutation[128] = {
	 89,126,112, 71,  4, 60, 22, 37,  6, 39, 41, 75, 77, 94, 40, 84,
	124, 59, 92, 96, 51, 26, 31, 52,127, 65, 63, 38, 68, 69,101, 36,
	 99,122,100, 19, 72, 61, 44, 73, 24,111, 25, 88,  7, 28,106, 32,
	 14, 98, 30,  0,104, 33, 78, 67,107, 74, 13,116, 15,103, 34,  3,
	 80,110, 91, 17,120,115, 46,119, 82, 57,  8, 76,105, 18, 43,109,
	 85, 95, 42,125,117, 87, 55, 54,  5, 29, 81,  1, 35,121, 10, 21,
	 11, 56, 20,102, 86, 47, 49, 83, 58, 70, 23, 12,  9,  2, 97, 53,
	 93, 45, 79, 27, 90, 62,113, 50, 48,118, 16,114, 66,123, 64,108,
};

shuffle_permutation()
{
	int temp, i, j;
	int bnum;
	long x;

	for (i = 0; i < SUPERSIZE; i++)
		tempkey[i] = xkey[i];
	for (i = 128; i > 0; ) {
		bnum = (i / 2) % SUPERSIZE;
		x = tempkey[bnum].left & 0x7fffffff;
			j = x % i;
			x = x / i;
			--i;
			temp = permutation[i];
			permutation[i] = permutation[j];
			permutation[j] = temp;
		tempkey[bnum].left = x;
		x = tempkey[bnum].right & 0x7fffffff;
			j = x % i;
			x = x / i;
			--i;
			temp = permutation[i];
			permutation[i] = permutation[j];
			permutation[j] = temp;
		tempkey[bnum].right = x;
	}
}
