/*
 *	CAST-128 in C
 *	Written by Steve Reid <sreid@sea-to-sky.net>
 *	100% Public Domain - no warranty
 *	Released 1997.10.11
 */

#include <stdio.h>
#include "cast.h"

int main(int argc, char** argv)
{
int i;
cast_key key;
u8 a[16] = {
	0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78,
	0x23, 0x45, 0x67, 0x89, 0x34, 0x56, 0x78, 0x9A
};
u8 b[16] = {
	0x01, 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78,
	0x23, 0x45, 0x67, 0x89, 0x34, 0x56, 0x78, 0x9A
};

	printf("Running maintenance test...\n");
	for (i = 0; i < 1000000; i++) {
		/* aL = encrypt(aL,b); aR = encrypt(aR,b); */
		cast_setkey(&key, b, 16);
		cast_encrypt(&key, &a[0], &a[0]);
		cast_encrypt(&key, &a[8], &a[8]);
		/* bL = encrypt(bL,a); bR = encrypt(bR,a); */
		cast_setkey(&key, a, 16);
		cast_encrypt(&key, &b[0], &b[0]);
		cast_encrypt(&key, &b[8], &b[8]);
	}

	printf("a = ");
	for (i = 0; i < 16; i++) {
		printf("%02X ", a[i]);
	}
	printf("\nb = ");
	for (i = 0; i < 16; i++) {
		printf("%02X ", b[i]);
	}

	printf("\nReversing test...\n");
	for (i = 0; i < 1000000; i++) {
		/* bL = decrypt(bL,a); bR = decrypt(bR,a); */
		cast_setkey(&key, a, 16);
		cast_decrypt(&key, &b[0], &b[0]);
		cast_decrypt(&key, &b[8], &b[8]);
		/* aL = decrypt(aL,b); aR = decrypt(aR,b); */
		cast_setkey(&key, b, 16);
		cast_decrypt(&key, &a[0], &a[0]);
		cast_decrypt(&key, &a[8], &a[8]);
	}

	printf("a = ");
	for (i = 0; i < 16; i++) {
		printf("%02X ", a[i]);
	}
	printf("\nb = ");
	for (i = 0; i < 16; i++) {
		printf("%02X ", b[i]);
	}
	printf("\n");

	return(0);
}

