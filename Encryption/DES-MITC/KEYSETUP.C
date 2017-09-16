/*
 *	DES Key Setup
 *	D.P.Mitchell  83/06/30.
 */

#include "crypt.h"

int subkeys[128];

int	pc1_c[] = {
	57,49,41,33,25,17, 9,
	 1,58,50,42,34,26,18,
	10, 2,59,51,43,35,27,
	19,11, 3,60,52,44,36,
};

int	pc1_d[] = {
	63,55,47,39,31,23,15,
	 7,62,54,46,38,30,22,
	14, 6,61,53,45,37,29,
	21,13, 5,28,20,12, 4,
};

int	shifts[] = {
	1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1,
};

int	pc2_c[] = {
	14,17,11,24, 1, 5,
	 3,28,15, 6,21,10,
	23,19,12, 4,26, 8,
	16, 7,27,20,13, 2,
};

int	pc2_d[] = {
	41,52,31,37,47,55,
	30,40,51,45,33,48,
	44,49,39,56,34,53,
	46,42,50,36,29,32,
};

key_setup(key, decrypting)
Block *key;
int decrypting;
{
	register round, j, k;
	register int *kl, *kh;
	int temp;
	int c[28], d[28];
	int keybits[64];

	/*
	 *	unpack 64-bit key block
	 */
	for (j = 0; j < 64; j++)
		if (j > 31)
			keybits[j] = ((key->right & (1 << (j - 32))) != 0);
		else
			keybits[j] = ((key->left & (1 << j)) != 0);
	/*
	 *	first permuted choice of 56 bits
	 */
	for (j = 0; j < 28; j++) {
		c[j] = keybits[pc1_c[j]-1];
		d[j] = keybits[pc1_d[j]-1];
	}
	/*
	 *	funny rotation of the 28-bit halves
	 */
	for (round = 0; round < 16; round++) {
		for (k = 0; k < shifts[round]; k++) {
			temp = c[0];
			for (j = 0; j < 27; j++)
				c[j] = c[j + 1];
			c[27] = temp;
			temp = d[0];
			for (j = 0; j < 27; j++)
				d[j] = d[j + 1];
			d[27] = temp;
		}
		/*
		 *	second permuted choice of 48 bits
		 */
		if (decrypting) {
			kl = &subkeys[8 * (15 - round)];
			kh = &subkeys[8 * (15 - round) + 4];
		} else {
			kl = &subkeys[8 * round];
			kh = &subkeys[8 * round + 4];
		}
		for (j = 0; j < 24; j += 6) {
			*kl++ =  c[pc2_c[j + 0] - 1]
			      + (c[pc2_c[j + 1] - 1] << 1)
			      + (c[pc2_c[j + 2] - 1] << 2)
			      + (c[pc2_c[j + 3] - 1] << 3)
			      + (c[pc2_c[j + 4] - 1] << 4)
			      + (c[pc2_c[j + 5] - 1] << 5);
			*kh++ =  d[pc2_d[j + 0] - 29]
			      + (d[pc2_d[j + 1] - 29] << 1)
			      + (d[pc2_d[j + 2] - 29] << 2)
			      + (d[pc2_d[j + 3] - 29] << 3)
			      + (d[pc2_d[j + 4] - 29] << 4)
			      + (d[pc2_d[j + 5] - 29] << 5);
		}
	}
}
