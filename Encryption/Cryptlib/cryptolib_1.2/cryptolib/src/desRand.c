/*
 * This is version 1.2 of CryptoLib
 *
 * The authors of this software are Jack Lacy, Don Mitchell and Matt Blaze
 *              Copyright (c) 1991, 1992, 1993, 1994, 1995 by AT&T.
 * Permission to use, copy, and modify this software without fee
 * is hereby granted, provided that this entire notice is included in
 * all copies of any software which is or includes a copy or
 * modification of this software and in all copies of the supporting
 * documentation for such software.
 *
 * NOTE:
 * Some of the algorithms in cryptolib may be covered by patents.
 * It is the responsibility of the user to ensure that any required
 * licenses are obtained.
 *
 *
 * SOME PARTS OF CRYPTOLIB MAY BE RESTRICTED UNDER UNITED STATES EXPORT
 * REGULATIONS.
 *
 *
 * THIS SOFTWARE IS BEING PROVIDED "AS IS", WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTY.  IN PARTICULAR, NEITHER THE AUTHORS NOR AT&T MAKE ANY
 * REPRESENTATION OR WARRANTY OF ANY KIND CONCERNING THE MERCHANTABILITY
 * OF THIS SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR PURPOSE.
 */
#include "libcrypt.h"

static unsigned char key[3][128];
static unsigned char prefix[20], suffix[20];
static BigInt counter;
static int first_time = 1;

#ifdef K_AND_R
_TYPE( void ) seedDesRandom(seed, seedlen)
  unsigned char *seed;
  int seedlen;
#else
_TYPE( void ) seedDesRandom(unsigned char *seed, int seedlen)
#endif
{
	static unsigned char short_key[3][8];
	unsigned char seedbuffer[64], *bp;

	if (seed != NULL) {
		/* Should have 64 bytes of seed material */
		if (seedlen < 64) {
			handle_exception(WARNING,
					 "seedDesRandom: need at least 64 bytes of seed material.\n");
			clib_memzero(seedbuffer, 64);
			clib_memcpy(seed, seedbuffer, seedlen);
		}
		else
			clib_memcpy(seed, seedbuffer, 64);

		bp = seedbuffer;
		clib_memcpy(bp, short_key[0], 8);
		bp += 8;
		clib_memcpy(bp, short_key[1], 8);
		bp += 8;
		clib_memcpy(bp, short_key[2], 8);
		bp += 8;
		clib_memcpy(bp, prefix, 20);
		bp += 20;
		clib_memcpy(bp, suffix, 20);
	}
	else {
		/* Get key material and suffix and prefix */

		randomBytes(short_key[0], 8, REALLY);
		randomBytes(short_key[1], 8, REALLY);
		randomBytes(short_key[2], 8, REALLY);
		randomBytes(prefix, 20, REALLY);
		randomBytes(suffix, 20, REALLY);
	}

	/* create extended keys */
	key_setup(short_key[0], key[0]);
	key_setup(short_key[1], key[1]);
	key_setup(short_key[2], key[2]);

	clib_memzero(short_key[0], 8);
	clib_memzero(short_key[1], 8);
	clib_memzero(short_key[2], 8);

	counter = bigInit(1);
	GUARANTEE(counter, 2);
	reset_big(counter, 1);
	first_time = 0;
}

_TYPE( unsigned long ) desRandom() {
	unsigned long retval;
	unsigned char maskbytes[48];
	unsigned char mask[8], counter_bytes[8];
	SHS_CTX context;

	/* Check to see if generator has been seeded or if the counter
	   has wrapped around */
	if (first_time) {
		seedDesRandom(NULL, 64);
	}
	clib_memzero(maskbytes, 48);
	clib_memzero(mask, 8);
	clib_memzero(counter_bytes, 8);
	
	/* Build maskbytes to be SHA digested */
	clib_memcpy(prefix, &maskbytes[28], 20);
	clib_memcpy(suffix, maskbytes, 20);

	/* move counter into array */
	bigToBuf(counter, 8, counter_bytes);
	clib_memcpy((unsigned char *)counter_bytes, &maskbytes[20], 8);

	/* digest */
	shsInit(&context);
	shsUpdate(&context, maskbytes, 48);
	shsFinal(&context);

	/* grab least significant 8 bytes */
	mask[0] = (unsigned char) (context.h[0] & 0xff);
	mask[1] = (unsigned char) ((context.h[0]>>8) & 0xff);
	mask[2] = (unsigned char) ((context.h[0]>>16) & 0xff);
	mask[3] = (unsigned char) ((context.h[0]>>24) & 0xff);
	mask[4] = (unsigned char) (context.h[1] & 0xff);
	mask[5] = (unsigned char) ((context.h[1]>>8) & 0xff);
	mask[6] = (unsigned char) ((context.h[1]>>16) & 0xff);
	mask[7] = (unsigned char) ((context.h[1]>>24) & 0xff);

	/* encrypt counter with global, static keys */
	triple_block_cipher(key, counter_bytes, 0);

	/* next value for counter */
	bigAdd(counter, one, counter);

	/* mask 3DES output with digest bytes */
	counter_bytes[0] ^= mask[0];
	counter_bytes[1] ^= mask[1];
	counter_bytes[2] ^= mask[2];
	counter_bytes[3] ^= mask[3];
	counter_bytes[4] ^= mask[4];
	counter_bytes[5] ^= mask[5];
	counter_bytes[6] ^= mask[6];
	counter_bytes[7] ^= mask[7];

	/* build unsigned long return value */
	retval = (unsigned long) (counter_bytes[3]);
	retval = (retval << 8) | (unsigned long)(counter_bytes[2]);
	retval = (retval << 8) | (unsigned long)(counter_bytes[1]);
	retval = (retval << 8) | (unsigned long)(counter_bytes[0]);

	/* clear counter_bytes */
	clib_memzero(counter_bytes, 8);

	return retval;
}


#ifdef DESRAND_DEBUG

void main(int argc, char **argv) {
	unsigned char seed[64];
	unsigned char buffer[1024*1024];
	unsigned char *cp;
	unsigned long ret;
	int i;
	FILE *fp = fopen("/tmp/desrand.out", "w");

	randomBytes(seed, 64, REALLY);
	seedDesRandom(seed);
	cp = buffer;
	for (i=0; i<1024*1024; i+=4) {
		ret = desRandom();
/*
		printf("%08lx\n", ret);
*/
		cp[0] = (unsigned char)(ret & 0xff);
		ret >>= 8;
		cp[1] = (unsigned char)(ret & 0xff);
		ret >>= 8;
		cp[2] = (unsigned char)(ret & 0xff);
		ret >>= 8;
		cp[3] = (unsigned char)(ret & 0xff);
		cp += 4;
	}
	fwrite(buffer, 1, 1024*1024, fp);
	fclose(fp);
}


#endif
