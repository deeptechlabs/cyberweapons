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

/*
 * Tools for creating keys for DES and doing Electronic Codebook,
 * Cipher Block Chaining and Output Feedback DES Modes.
 *
 * coded by D.P. Mitchell and Jack Lacy 12/91
 */

#include "libcrypt.h"
#include <stdlib.h>

extern 

#ifdef K_AND_R
_TYPE( void )
key_crunch(buffer, size, key)
  unsigned char buffer[], key[];
  int size;
#else
_TYPE( void ) key_crunch(unsigned char buffer[],
			 int size,
			 unsigned char key[])
#endif
{
	register int i;
	unsigned char int_key[128];
	
	clib_memzero(int_key, 128);
	clib_memzero(key, 8);
	key_setup((unsigned char *)"canofbu", int_key);
	
	for (i = 0; i < size; i++) {
		key[(i & 7)] ^= buffer[i];
		if ((i & 7) == 7)
			block_cipher(int_key, key, 0);
	}
	block_cipher(int_key, key, 0);
}


#ifdef K_AND_R
_TYPE( void )
setupDESState(state, key, icv, mode)
  DESState *state;
  unsigned char *key, *icv;
  ModeType mode;
#else
_TYPE( void ) setupDESState(DESState *state,
			    unsigned char *key,
			    unsigned char *icv,
			    ModeType mode)
#endif
{
	memset(state, 0, sizeof(*state));
	state->mode = mode;
	key_setup(key, state->int_key);
	if (icv)
		clib_memcpy(icv, state->icv, 8);
	state->count = 0;
	state->setup = 0xdeadbeef;

}


#ifdef K_AND_R
_TYPE( void )
setupTripleDESState(state, key, icv, mode)
  TripleDESState *state;
  unsigned char *key[3], *icv;
  ModeType mode;
#else
_TYPE( void ) setupTripleDESState(TripleDESState *state,
				  unsigned char *key[3],
				  unsigned char *icv,
				  ModeType mode)
#endif
{
	memset(state, 0, sizeof(*state));
	state->mode = mode;
	key_setup(key[0], state->int_key[0]);
	key_setup(key[1], state->int_key[1]);
	key_setup(key[2], state->int_key[2]);
	if (icv)
		clib_memcpy(icv, state->icv, 8);
	state->count = 0;
	state->setup = 0xdeadbeef;

}


#ifdef K_AND_R
_TYPE( void )
clearDESState(state)
  DESState *state;
#else
_TYPE( void ) clearDESState(DESState *state)
#endif
{
	state->mode = 0;
	clib_memzero((unsigned char *)state, sizeof(*state));
	state->count = 0;
	state->setup = 0;
}


#ifdef K_AND_R
_TYPE( void )
blockECBEncrypt(in, state)
  unsigned char in[];
  DESState *state;
#else
_TYPE( void ) blockECBEncrypt(unsigned char in[],
			      DESState *state)
#endif
{

	block_cipher(state->int_key, in, 0);
}

#ifdef K_AND_R
_TYPE( void )
blockECBDecrypt(in, state)
  unsigned char in[];
  DESState *state;
#else
_TYPE( void ) blockECBDecrypt(unsigned char in[],
			      DESState *state)
#endif
{
	
	block_cipher(state->int_key, in, 1);
}

#ifdef K_AND_R
_TYPE( void )
blockCBCEncrypt(in, state)
  unsigned char in[8];
  DESState *state;
#else
_TYPE( void ) blockCBCEncrypt(unsigned char in[8],
			      DESState *state)
#endif
{
	register int j;
	
	if (state->count == 8) {
		for (j=0; j < 8; j++)
			in[j] ^= state->icv[j];
		block_cipher(state->int_key, in, 0);
		for (j=0; j < 8; j++)
			state->icv[j] = in[j];
	}
	else {
		block_cipher(state->int_key, state->icv, 0);
		for (j = 0; j < state->count; j++)
			in[j] ^= state->icv[j];
	}
	
}

#ifdef K_AND_R
_TYPE( void )
blockCBCDecrypt(in, state)
  unsigned char in[8];
  DESState *state;
#else
_TYPE( void ) blockCBCDecrypt(unsigned char in[8],
			      DESState *state)
#endif
{
	unsigned char tmp[8];
	register int j;
	
	if (state->count == 8) {
		for (j=0; j < 8; j++)
			tmp[j] = in[j];
		block_cipher(state->int_key, in, 1);
		for (j=0; j < 8; j++) {
			in[j] ^= state->icv[j];
			state->icv[j] = tmp[j];
		}
	}
	else {
		block_cipher(state->int_key, state->icv, 0);
		for (j = 0; j < state->count; j++)
			in[j] ^= state->icv[j];
	}
	
}


#ifdef K_AND_R
_TYPE( void )
blockOFMEncrypt(in, state)
  unsigned char in[8];
  DESState *state;
#else
_TYPE( void ) blockOFMEncrypt(unsigned char in[8],
			  DESState *state)
#endif
{
	register unsigned char c;
	register int j, chunk;
	
	while (state->count > 0) {
		block_cipher(state->int_key, state->icv, 0);
		chunk = (state->count >= 8? 8: state->count);
		for (j=0; j < chunk; j++) {
			c = in[j];
			c ^= state->icv[j];
			in[j] = c;
		}
		state->count -= 8;
	}
}


#ifdef K_AND_R
_TYPE( void )
blockOFMDecrypt(in, state)
  unsigned char in[];
  DESState *state;
#else
_TYPE( void ) blockOFMDecrypt(unsigned char in[],
			      DESState *state)
#endif
{
	blockOFMEncrypt(in, state);
}


#ifdef K_AND_R
_TYPE( void )
bufferECBEncrypt(buf, key, len, state)
  unsigned char *buf;
  int len;
  DESState *state;
#else
_TYPE( void ) bufferECBEncrypt(unsigned char *buf,
			       int len,
			       DESState *state)
#endif
{
	register unsigned char *block;
	unsigned char tmp[8];
	register int i;
	
	for (i=8, block=buf; i<=len; i+=8, block+=8)
		blockECBEncrypt(block, state);
	
	if ((len & 7) != 0) {
		for (i=0; i<8; i++)
			tmp[i] = i;
		blockECBEncrypt(tmp, state);
		for (i=0; i<(len&7); i++)
			block[i] ^= tmp[i];
	}
	
}

#ifdef K_AND_R
_TYPE( void )
bufferECBDecrypt(buf, len, state)
  unsigned char *buf;
  int len;
  DESState *state;
#else
_TYPE( void ) bufferECBDecrypt(unsigned char *buf,
			       int len,
			       DESState *state)
#endif
{
	register unsigned char *block;
	unsigned char tmp[8];
	register int i;
	
	for (i=8, block=buf; i<=len; i+=8, block+=8)
		blockECBDecrypt(block, state);
	
	if ((len & 7) != 0) {
		for (i=0; i<8; i++)
			tmp[i] = i;
		blockECBEncrypt(tmp, state);
		for (i=0; i<(len&7); i++)
			block[i] ^= tmp[i];
	}
}

#ifdef K_AND_R
_TYPE( void )
bufferCBCEncrypt(buf, len, state)
  unsigned char *buf;
  int len;
  DESState *state;
#else
_TYPE( void ) bufferCBCEncrypt(unsigned char *buf,
			       int len,
			       DESState *state)
#endif
{
	unsigned char *block;
	register int i;
	
	state->count = 8;
	for (i=8, block=buf; i<=len; i+=8, block+=8) 
		blockCBCEncrypt(block, state);
	
	state->count = len&7;
	if ((len & 7) != 0)
		blockCBCEncrypt(block, state);
	
}

#ifdef K_AND_R
_TYPE( void )
bufferCBCDecrypt(buf, len, state)
  unsigned char *buf;
  int len;
  DESState *state;
#else
_TYPE( void ) bufferCBCDecrypt(unsigned char *buf,
			       int len,
			       DESState *state)
#endif
{
	unsigned char *block;
	register int i;
	
	state->count = 8;
	for (i=8, block=buf; i<=len; i+=8, block+=8)
		blockCBCDecrypt(block, state);
	
	state->count = len&7;
	if ((len & 7) != 0)
		blockCBCDecrypt(block, state);
	
}

#ifdef K_AND_R
_TYPE( void )
bufferOFMEncrypt(buf, len, state)
  unsigned char *buf;
  int len;
  DESState *state;
#else
_TYPE( void ) bufferOFMEncrypt(unsigned char *buf,
			       int len,
			       DESState *state)
#endif
{
	unsigned char *block;
	register int i;
	
	for (i=8, block=buf; i<=len; i+=8, block+=8) {
		state->count = 8;
		blockOFMEncrypt(block, state);
	}
	
	state->count = len&7;
	if ((len & 7) != 0)
		blockOFMEncrypt(block, state);
	
}

#ifdef K_AND_R
_TYPE( void )
bufferOFMDecrypt(buf, len, state)
  unsigned char *buf;
  int len;
  DESState *state;
#else
_TYPE( void ) bufferOFMDecrypt(unsigned char *buf,
			       int len,
			       DESState *state)
#endif
{
	bufferOFMEncrypt(buf, len, state);
}



/* Triple DES functions */

#ifdef K_AND_R
_TYPE( void )
block3ECBEncrypt(block, state)
  unsigned char block[8];
  TripleDESState *state;
#else
_TYPE( void ) block3ECBEncrypt(unsigned char block[8],
			       TripleDESState *state)
#endif
{
	
	triple_block_cipher(state->int_key, block, 0);
}

#ifdef K_AND_R
_TYPE( void )
block3ECBDecrypt(block, state)
  unsigned char block[8];
  TripleDESState *state;
#else
_TYPE( void ) block3ECBDecrypt(unsigned char block[8],
			       TripleDESState *state)
#endif
{
	
	triple_block_cipher(state->int_key, block, 1);
}

#ifdef K_AND_R
_TYPE( void )
block3CBCEncrypt(in, state)
  unsigned char in[8];
  TripleDESState *state;
#else
_TYPE( void ) block3CBCEncrypt(unsigned char in[8],
			       TripleDESState *state)
#endif
{
	register int j;
	
	if (state->count == 8) {
		for (j=0; j < 8; j++)
			in[j] ^= state->icv[j];
		triple_block_cipher(state->int_key, in, 0);
		for (j=0; j < 8; j++)
			state->icv[j] = in[j];
	}
	else {
		triple_block_cipher(state->int_key, state->icv, 0);
		for (j = 0; j < state->count; j++)
			in[j] ^= state->icv[j];
	}
	
}

#ifdef K_AND_R
_TYPE( void )
block3CBCDecrypt(in, state)
  unsigned char in[8];
  TripleDESState *state;
#else
_TYPE( void ) block3CBCDecrypt(unsigned char in[8],
			       TripleDESState *state)
#endif
{
	unsigned char tmp[8];
	register int j;
	
	if (state->count == 8) {
		for (j=0; j < 8; j++)
			tmp[j] = in[j];
		triple_block_cipher(state->int_key, in, 1);
		for (j=0; j < 8; j++) {
			in[j] ^= state->icv[j];
			state->icv[j] = tmp[j];
		}
	}
	else {
		triple_block_cipher(state->int_key, state->icv, 0);
		for (j = 0; j < state->count; j++)
			in[j] ^= state->icv[j];
	}
	
}

#ifdef K_AND_R
_TYPE( void )
block3OFMEncrypt(in, state)
  unsigned char in[8];
  TripleDESState *state;
#else
_TYPE( void ) block3OFMEncrypt(unsigned char in[8],
			       TripleDESState *state)
#endif
{
	register unsigned char c;
	register int j, chunk;
	
	while (state->count > 0) {
		triple_block_cipher(state->int_key, state->icv, 0);
		chunk = (state->count >= 8? 8: state->count);
		for (j=0; j < chunk; j++) {
			c = in[j];
			c ^= state->icv[j];
			in[j] = c;
		}
		state->count -= 8;
	}
}


#ifdef K_AND_R
_TYPE( void )
block3OFMDecrypt(block, state)
  unsigned char block[8];
  TripleDESState *state;
#else
_TYPE( void ) block3OFMDecrypt(unsigned char block[8],
			       TripleDESState *state)
#endif
{
	block3OFMEncrypt(block, state);
}

#ifdef K_AND_R
_TYPE( void )
buffer3ECBEncrypt(buf, len, state)
  unsigned char *buf;
  int len;
  TripleDESState *state;
#else
_TYPE( void ) buffer3ECBEncrypt(unsigned char *buf,
				int len,
				TripleDESState *state)
#endif
{
	register unsigned char *block;
	unsigned char tmp[8];
	register int i;
	
	for (i=8, block=buf; i<=len; i+=8, block+=8) {
		triple_block_cipher(state->int_key, block, 0);
	}
	
	if ((len & 7) != 0) {
		for (i=0; i<8; i++)
			tmp[i] = i;
		triple_block_cipher(state->int_key, tmp, 0);
		
		for (i=0; i<(len&7); i++)
			block[i] ^= tmp[i];
	}
	
}

#ifdef K_AND_R
_TYPE( void )
buffer3ECBDecrypt(buf, len, state)
  unsigned char *buf;
  int len;
  TripleDESState *state;
#else
_TYPE( void ) buffer3ECBDecrypt(unsigned char *buf,
				int len,
				TripleDESState *state)
#endif
{
	register unsigned char *block;
	unsigned char tmp[8];
	register int i;
	
	for (i=8, block=buf; i<=len; i+=8, block+=8) {
		triple_block_cipher(state->int_key, block, 1);
	}
	
	if ((len & 7) != 0) {
		for (i=0; i<8; i++)
			tmp[i] = i;
		triple_block_cipher(state->int_key, tmp, 0);
		
		for (i=0; i<(len&7); i++)
			block[i] ^= tmp[i];
	}
}

#ifdef K_AND_R
_TYPE( void )
buffer3CBCEncrypt(buf, len, state)
  unsigned char *buf;
  int len;
  TripleDESState *state;
#else
_TYPE( void ) buffer3CBCEncrypt(unsigned char *buf,
				int len,
				TripleDESState *state)
#endif
{
	unsigned char *block;
	register int i;
	
	for (i=8, block=buf; i<=len; i+=8, block+=8) {
		state->count = 8;
		block3CBCEncrypt(block, state);
	}
	if ((len & 7) != 0) {
		state->count = len&7;
		block3CBCEncrypt(block, state);
	}
}

#ifdef K_AND_R
_TYPE( void )
buffer3CBCDecrypt(buf, len, state)
  unsigned char *buf;
  int len;
  TripleDESState *state;
#else
_TYPE( void ) buffer3CBCDecrypt(unsigned char *buf,
				int len,
				TripleDESState *state)
#endif
{
	unsigned char *block;
	register int i;
	
	for (i=8, block=buf; i<=len; i+=8, block+=8) {
		state->count = 8;
		block3CBCDecrypt(block, state);
	}
	if ((len & 7) != 0) {
		state->count = len&7;
		block3CBCDecrypt(block, state);
	}
}

#ifdef K_AND_R
_TYPE( void )
buffer3OFMEncrypt(buf, len, state)
  unsigned char *buf;
  int len;
  TripleDESState *state;
#else
_TYPE( void ) buffer3OFMEncrypt(unsigned char *buf,
				int len,
				TripleDESState *state)
#endif
{
	unsigned char *block;
	register int i;
	
	for (i=8, block=buf; i<=len; i+=8, block+=8) {
		state->count = 8;
		block3OFMDecrypt(block, state);
	}
	if ((len & 7) != 0) {
		state->count = len&7;
		block3OFMDecrypt(block, state);
	}
}

#ifdef K_AND_R
_TYPE( void )
buffer3OFMDecrypt(buf, len, state)
  unsigned char *buf;
  int len;
  TripleDESState *state;
#else
_TYPE( void ) buffer3OFMDecrypt(unsigned char *buf,
				int len,
				TripleDESState *state)
#endif
{
	buffer3OFMEncrypt(buf, len, state);
}


#ifdef K_AND_R
_TYPE( void )
bignumDesEncrypt(big, key)
  BigInt big;
  unsigned char key[8];
#else
_TYPE( void ) bignumDesEncrypt(BigInt big,
			       unsigned char key[8])
#endif
{
	DESState state;
	unsigned char *buf;
	int length;
#ifdef DLLEXPORT
	HGLOBAL handle = clib_malloc(bigBytes(big));
	buf = (unsigned char *)GlobalLock(handle);
#else
	buf = (unsigned char *)clib_malloc(bigBytes(big));
#endif
	
	length = bigBytes(big);
	bigToBuf(big, length, buf);
	setupDESState(&state, key, (unsigned char *)NULL, ECB);
	bufferEncrypt(buf, length, &state);
	bufToBig(buf, length, big);
#ifdef DLLEXPORT
	clib_memzero(buf, length);
	GlobalUnlock(handle);
	GlobalFree(handle);
#else
	free(buf);
#endif
}

#ifdef K_AND_R
_TYPE( void )
bignumDesDecrypt(big, key)
  BigInt big;
  unsigned char key[8];
#else
_TYPE( void ) bignumDesDecrypt(BigInt big,
			       unsigned char key[8])
#endif
{
	DESState state;
	unsigned char *buf;
	int length;
#ifdef DLLEXPORT
	HGLOBAL handle = clib_malloc(bigBytes(big));
	buf = (unsigned char *)GlobalLock(handle);
#else
	buf = (unsigned char *)clib_malloc(bigBytes(big));
#endif
	length = bigBytes(big);
	bigToBuf(big, length, buf);
	setupDESState(&state, key, (unsigned char *)NULL, ECB);
	bufferDecrypt(buf, (int)length, &state);
	bufToBig(buf, length, big);
	
#ifdef DLLEXPORT
	clib_memzero(buf, length);
	GlobalUnlock(handle);
	GlobalFree(handle);
#else
	free(buf);
#endif
}


#ifdef K_AND_R
_TYPE( void )
bignumCBCDesEncrypt(big, key)
  BigInt big;
  unsigned char key[8];
#else
_TYPE( void ) bignumCBCDesEncrypt(BigInt big,
				  unsigned char key[8])
#endif
{
	DESState state;
	unsigned char *buf, icv[8];
	unsigned int length;
	
	length = bigBytes(big);
	buf = (unsigned char *)clib_malloc((unsigned)(length+8));
	
	clib_memzero(icv, 8);
	randomBytes(buf, 8, PSEUDO);
	bigToBuf(big, length, buf+8);
	setupDESState(&state, key, icv, CBC);
	bufferCBCEncrypt(buf, (int)(length+8), &state);
	bufToBig(buf, (unsigned int)(length+8), big);
	
	clib_memzero(icv, 8);
	clib_memzero(buf, length+8);
	clib_memzero((unsigned char *)&state, sizeof(state));
	free(buf);
}

#ifdef K_AND_R
_TYPE( void )
bignumCBCDesDecrypt(big, key)
  BigInt big;
  unsigned char key[8];
#else
_TYPE( void ) bignumCBCDesDecrypt(BigInt big,
				  unsigned char key[8])
#endif
{
	DESState state;
	unsigned char *buf, icv[8];
	unsigned int length;
	
	length = bigBytes(big);
	buf = (unsigned char *)clib_malloc((unsigned)length);
	
	clib_memzero(icv, 8);
	bigToBuf(big, length, buf);
	setupDESState(&state, key, icv, CBC);
	bufferCBCDecrypt(buf, (int)length, &state);
	bufToBig(buf+8, (unsigned int)(length-8), big);
	
	clib_memzero(icv, 8);
	clib_memzero(buf, length);
	clib_memzero((unsigned char *)&state, sizeof(state));
	free(buf);
}




/* Cipher Feedback Mode support functions */

#ifdef K_AND_R
static void
eightBitCFMEncrypt(in, sreg, key)
  unsigned char in[8], sreg[8], key[128];
#else
static void eightBitCFMEncrypt(unsigned char in[8],
			       unsigned char sreg[8],
			       unsigned char key[128])
#endif
{
	
	in[0] ^= sreg[0];
	sreg[0] = sreg[1];
	sreg[1] = sreg[2];
	sreg[2] = sreg[3];
	sreg[3] = sreg[4];
	sreg[4] = sreg[5];
	sreg[5] = sreg[6];
	sreg[6] = sreg[7];
	sreg[7] = in[0];
	block_cipher(key, sreg, 0);
	
}

#ifdef K_AND_R
static void
eightBitCFMDecrypt(in, sreg, key)
  unsigned char in[8], sreg[8], key[128];
#else
static void eightBitCFMDecrypt(unsigned char in[8],
			       unsigned char sreg[8],
			       unsigned char key[128])
#endif
{
	
	unsigned char c = in[0];

	in[0] ^= sreg[0];
	sreg[0] = sreg[1];
	sreg[1] = sreg[2];
	sreg[2] = sreg[3];
	sreg[3] = sreg[4];
	sreg[4] = sreg[5];
	sreg[5] = sreg[6];
	sreg[6] = sreg[7];
	sreg[7] = c;
	block_cipher(key, sreg, 0);
	
}



#ifdef K_AND_R
_TYPE( void )
blockEightBitCFMEncrypt(in, len, sreg, key)
  unsigned char in[], sreg[], key[];
  int len;
#else
_TYPE( void ) blockEightBitCFMEncrypt(unsigned char in[],
				      int len,
				      unsigned char sreg[],
				      unsigned char key[])
#endif
{
	static unsigned char old_key[8];
	static unsigned char int_key[128];
	unsigned char inbuf[1];
	int i;
	
	if (clib_memcmp(old_key, key, 8) != 0) {
		clib_memcpy(key, old_key, 8);
		key_setup(key, int_key);
	}
	for (i=0; i<len; i++) {
		inbuf[0] = in[i];
		eightBitCFMEncrypt(inbuf, sreg, int_key);
		in[i] = inbuf[0];
	}
}


#ifdef K_AND_R
_TYPE( void )
blockEightBitCFMDecrypt(in, len, sreg, key)
  unsigned char in[], sreg[], key[];
  int len;
#else
_TYPE( void ) blockEightBitCFMDecrypt(unsigned char in[],
				      int len,
				      unsigned char sreg[],
				      unsigned char key[])
#endif
{
	static unsigned char old_key[8];
	static unsigned char int_key[128];
	unsigned char inbuf[1];
	int i;
	
	if (clib_memcmp(old_key, key, 8) != 0) {
		clib_memcpy(key, old_key, 8);
		key_setup(key, int_key);
	}
	for (i=0; i<len; i++) {
		inbuf[0] = in[i];
		eightBitCFMDecrypt(inbuf, sreg, int_key);
		in[i] = inbuf[0];
	}
}

#ifdef K_AND_R
static void
sixtyFourBitCFMEncrypt(in, sreg, key)
  unsigned char in[8], sreg[8], key[128];
#else
static void sixtyFourBitCFMEncrypt(unsigned char in[8],
				   unsigned char sreg[8],
				   unsigned char key[128])
#endif
{
	
	in[0] ^= sreg[0];
	in[1] ^= sreg[1];
	in[2] ^= sreg[2];
	in[3] ^= sreg[3];
	in[4] ^= sreg[4];
	in[5] ^= sreg[5];
	in[6] ^= sreg[6];
	in[7] ^= sreg[7];
	clib_memcpy(in, sreg, 8);
	block_cipher(key, sreg, 0);
}

#ifdef K_AND_R
static void
sixtyFourBitCFMDecrypt(in, sreg, key)
  unsigned char in[8], sreg[8], key[128];
#else
static void sixtyFourBitCFMDecrypt(unsigned char in[8],
				   unsigned char sreg[8],
				   unsigned char key[128])
#endif
{
	
	unsigned char tmp[8];

	clib_memcpy(in, tmp, 8);
	in[0] ^= sreg[0];
	in[1] ^= sreg[1];
	in[2] ^= sreg[2];
	in[3] ^= sreg[3];
	in[4] ^= sreg[4];
	in[5] ^= sreg[5];
	in[6] ^= sreg[6];
	in[7] ^= sreg[7];
	clib_memcpy(tmp, sreg, 8);
	block_cipher(key, sreg, 0);
	
}


#ifdef K_AND_R
_TYPE( void )
blockSixtyFourBitCFMEncrypt(in, len, sreg, key)
  unsigned char in[], sreg[], key[];
  int len;
#else
_TYPE( void ) blockSixtyFourBitCFMEncrypt(unsigned char in[],
					  int len,
					  unsigned char sreg[],
					  unsigned char key[])
#endif
{
	static unsigned char old_key[8];
	static unsigned char int_key[128];
	
	if (clib_memcmp(old_key, key, 8) != 0) {
		clib_memcpy(key, old_key, 8);
		key_setup(key, int_key);
	}
	sixtyFourBitCFMEncrypt(in, sreg, int_key);
}


#ifdef K_AND_R
_TYPE( void )
blockSixtyFourBitCFMDecrypt(in, len, sreg, key)
  unsigned char in[], sreg[], key[];
  int len;
#else
_TYPE( void ) blockSixtyFourBitCFMDecrypt(unsigned char in[],
					  int len,
					  unsigned char sreg[],
					  unsigned char key[])
#endif
{
	static unsigned char old_key[8];
	static unsigned char int_key[128];
	
	if (clib_memcmp(old_key, key, 8) != 0) {
		clib_memcpy(key, old_key, 8);
		key_setup(key, int_key);
	}
	sixtyFourBitCFMDecrypt(in, sreg, int_key);
}



/* Block and Buffer DES and 3-DES interfaces */

/* single-DES interface */

#ifdef K_AND_R
_TYPE( void )
blockEncrypt(in, state)
  unsigned char in[];
  DESState *state;
#else
_TYPE( void ) blockEncrypt(unsigned char in[],
			   DESState *state)
#endif
{
	switch(state->mode) {
	    case ECB:
		blockECBEncrypt(in, state);
		break;
	    case CBC:
		blockCBCEncrypt(in, state);
		break;
	    case OFM:
		blockOFMEncrypt(in, state);
		break;
	    default:
		handle_exception(CRITICAL, "blockEncrypt: unknown mode\n");
	}
}



#ifdef K_AND_R
_TYPE( void )
blockDecrypt(in, state)
  unsigned char in[];
  DESState *state;
#else
_TYPE( void ) blockDecrypt(unsigned char in[],
			   DESState *state)
#endif
{
	switch(state->mode) {
	    case ECB:
		blockECBDecrypt(in, state);
		break;
	    case CBC:
		blockCBCDecrypt(in, state);
		break;
	    case OFM:
		blockOFMDecrypt(in, state);
		break;
	    default:
		handle_exception(CRITICAL, "blockDecrypt: unknown mode\n");
	}
}

#ifdef K_AND_R
_TYPE( void )
bufferEncrypt(in, len, state)
  unsigned char in[];
  int len;
  DESState *state;
#else
_TYPE( void ) bufferEncrypt(unsigned char in[],
			    int len,
			    DESState *state)
#endif
{
	switch(state->mode) {
	    case ECB:
		bufferECBEncrypt(in, len, state);
		break;
	    case CBC:
		bufferCBCEncrypt(in, len, state);
		break;
	    case OFM:
		bufferOFMEncrypt(in, len, state);
		break;
	    default:
		handle_exception(CRITICAL, "bufferEncrypt: unknown mode\n");
	}
}



#ifdef K_AND_R
_TYPE( void )
bufferDecrypt(in, len, state)
  unsigned char in[];
  int len;
  DESState *state;
#else
_TYPE( void ) bufferDecrypt(unsigned char in[],
			    int len,
			    DESState *state)
#endif
{
	switch(state->mode) {
	    case ECB:
		bufferECBDecrypt(in, len, state);
		break;
	    case CBC:
		bufferCBCDecrypt(in, len, state);
		break;
	    case OFM:
		bufferOFMDecrypt(in, len, state);
		break;
	    default:
		handle_exception(CRITICAL, "bufferDecrypt: unknown mode\n");
	}
}


/* 3-DES interface */

#ifdef K_AND_R
_TYPE( void )
block3Encrypt(in, state)
  unsigned char in[];
  TripleDESState *state;
#else
_TYPE( void ) block3Encrypt(unsigned char in[],
			    TripleDESState *state)
#endif
{
	switch(state->mode) {
	    case ECB3:
		block3ECBEncrypt(in, state);
		break;
	    case CBC3:
		block3CBCEncrypt(in, state);
		break;
	    case OFM3:
		block3OFMEncrypt(in, state);
		break;
	    default:
		handle_exception(CRITICAL, "block3Encrypt: unknown mode\n");
	}
}



#ifdef K_AND_R
_TYPE( void )
block3Decrypt(in, state)
  unsigned char in[];
  TripleDESState *state;
#else
_TYPE( void ) block3Decrypt(unsigned char in[],
			   TripleDESState *state)
#endif
{
	switch(state->mode) {
	    case ECB3:
		block3ECBDecrypt(in, state);
		break;
	    case CBC3:
		block3CBCDecrypt(in, state);
		break;
	    case OFM3:
		block3OFMDecrypt(in, state);
		break;
	    default:
		handle_exception(CRITICAL, "block3Decrypt: unknown mode\n");
	}
}

#ifdef K_AND_R
_TYPE( void )
buffer3Encrypt(in, len, state)
  unsigned char in[];
  int len;
  TripleDESState *state;
#else
_TYPE( void ) buffer3Encrypt(unsigned char in[],
			     int len,
			     TripleDESState *state)
#endif
{
	switch(state->mode) {
	    case ECB3:
		buffer3ECBEncrypt(in, len, state);
		break;
	    case CBC3:
		buffer3CBCEncrypt(in, len, state);
		break;
	    case OFM3:
		buffer3OFMEncrypt(in, len, state);
		break;
	    default:
		handle_exception(CRITICAL, "buffer3Decrypt: unknown mode\n");
	}
}



#ifdef K_AND_R
_TYPE( void )
buffer3Decrypt(in, len, state)
  unsigned char in[];
  int len;
  TripleDESState *state;
#else
_TYPE( void ) buffer3Decrypt(unsigned char in[],
			     int len,
			     TripleDESState *state)
#endif
{
	switch(state->mode) {
	    case ECB3:
		buffer3ECBDecrypt(in, len, state);
		break;
	    case CBC3:
		buffer3CBCDecrypt(in, len, state);
		break;
	    case OFM3:
		buffer3OFMDecrypt(in, len, state);
		break;
	    default:
		handle_exception(CRITICAL, "buffer3Decrypt: unknown mode\n");
	}
}


