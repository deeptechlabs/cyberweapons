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
 *	Feedback shift register pseudorandom number
 *	generator by D.P. Mitchell and Jack Lacy.
 *	Copyright (c) 1991 AT&T Bell Laboratories
 */
#include "libcrypt.h"

/* Feedback Shift Register and DES based pseudoRand */

#define FSR_MAX 7
#define UPPER_INDEX 6
#define LOWER_INDEX 2
#define REAL_INIT_BYTES FSR_MAX*4

static unsigned char RANDKEY[128];
static unsigned long fsr[FSR_MAX];
static int rand_key_set = 0;
static int fsr_loaded = 0;
static void init_fsrrand P((void));

/*
static unsigned long init_fsr[55] = {
	0x491fcfddUL,0xf36ad4bcUL,0x27adffddUL,0x8bc1bfdeUL,0xcc4cd9afUL,
	0x942e7bcfUL,0x59115271UL,0x7eb44cc2UL,0x08224962UL,0x74bcb091UL,
	0xfd9efedcUL,0x08e8135cUL,0xa12e27a5UL,0x0c06367fUL,0x67966a76UL,
	0x692c9559UL,0x629d82b2UL,0x62363f36UL,0xbfff3330UL,0xea1242afUL,
	0x59e1d1b0UL,0x282ee969UL,0x0f1399dfUL,0x97aceac7UL,0x07c44f1eUL,
	0x0afd53eaUL,0x0bef3079UL,0xd6662669UL,0x735be859UL,0xc591eabfUL,
	0x84ff845fUL,0x8a894a78UL,0x34c8f257UL,0xb85bce47UL,0x65989b54UL,
	0x87ac1eb4UL,0x06949770UL,0x0dd27f9eUL,0xda749d55UL,0xa360a339UL,
	0x05829596UL,0x00da965fUL,0x5b4166e7UL,0x4b57d1f5UL,0x4c20d47cUL,
	0x0aca3e61UL,0x078f2e19UL,0x06519a99UL,0x6c244574UL,0x19472f3aUL,
	0x375c6265UL,0x1625869bUL,0x09c0cf3dUL,0x092556c3UL,0x26448cfaUL,
};
*/
static unsigned long init_fsr[55] = {
	0x491fcfdd,0xf36ad4bc,0x27adffdd,0x8bc1bfde,0xcc4cd9af,
	0x942e7bcf,0x59115271,0x7eb44cc2,0x08224962,0x74bcb091,
	0xfd9efedc,0x08e8135c,0xa12e27a5,0x0c06367f,0x67966a76,
	0x692c9559,0x629d82b2,0x62363f36,0xbfff3330,0xea1242af,
	0x59e1d1b0,0x282ee969,0x0f1399df,0x97aceac7,0x07c44f1e,
	0x0afd53ea,0x0bef3079,0xd6662669,0x735be859,0xc591eabf,
	0x84ff845f,0x8a894a78,0x34c8f257,0xb85bce47,0x65989b54,
	0x87ac1eb4,0x06949770,0x0dd27f9e,0xda749d55,0xa360a339,
	0x05829596,0x00da965f,0x5b4166e7,0x4b57d1f5,0x4c20d47c,
	0x0aca3e61,0x078f2e19,0x06519a99,0x6c244574,0x19472f3a,
	0x375c6265,0x1625869b,0x09c0cf3d,0x092556c3,0x26448cfa,
};

/*
   static void
   fsr_print() {
   register long i;
   FILE *fp = stdout;
   
   for (i=0; i<FSR_MAX; i++) {
   fprintf(fp, "%08lx\n",fsr[i]);
   }
   }
   */
#ifdef K_AND_R
_TYPE( void )
seed_fsr(seed, seedlen)
  unsigned char *seed;
  int seedlen;
#else
_TYPE( void ) seed_fsr(unsigned char *seed,
		       int seedlen)
#endif
{
	register int i, j;
	int log_fsrmax = 3; /* log 7 */
	unsigned char rk[8];
	
	if (rand_key_set == 0) {
		key_crunch((unsigned char *)seed, seedlen, rk);
		key_setup(rk, RANDKEY);
		for (i=0; i<8; i++)
			rk[i] = 0;
		rand_key_set = 1;
	}
	
	for (i=0; i<FSR_MAX; i++) {
		fsr[i] = init_fsr[i];
	}
	
	for (i=0; i<seedlen; i++) {
		fsr[i%FSR_MAX] ^= ((unsigned long)(seed[i]&0xff) << ((i%4)*8));
	}
	
	fsr_loaded = 1;
	for (i=0; i<log_fsrmax; i++)
		for (j=0; j<FSR_MAX; j++)
			fsrRandom();
}

static
void init_fsrrand() {
	unsigned char *load_vector, *rk;
	int i;
#ifdef DLLEXPORT
	HGLOBAL rk_handle = clib_malloc(8);
	HGLOBAL lv_handle = clib_malloc(REAL_INIT_BYTES);
	rk = (unsigned char *)GlobalLock(rk_handle);
	load_vector = (unsigned char *)GlobalLock(lv_handle);
#else
	rk = (unsigned char *)malloc(8);
	load_vector = (unsigned char *)malloc(REAL_INIT_BYTES);
#endif
	randomBytes(rk, 8, REALLY);
	key_setup((unsigned char *)rk, RANDKEY);
	for (i=0; i<8; i++)
		rk[i] = 0;
	rand_key_set = 1;
	
	randomBytes(load_vector, REAL_INIT_BYTES, REALLY);
	seed_fsr((unsigned char *)load_vector, REAL_INIT_BYTES);
	
	for (i=0; i<REAL_INIT_BYTES; i++)
		load_vector[i] = 0;
#ifdef DLLEXPORT
	GlobalUnlock(rk_handle);
	GlobalUnlock(lv_handle);
	GlobalFree(rk_handle);
	GlobalFree(lv_handle);
#else
	free(rk);
	free(load_vector);
#endif
	fsr_loaded = 1;
}

static int li = LOWER_INDEX;
static int ui = UPPER_INDEX;

_TYPE( unsigned long )
fsrRandom() {
	register unsigned long uip, lip;
	static unsigned char block[8];
	unsigned long retval;
	register int i;
	
	if (fsr_loaded == 0) {
		init_fsrrand();
	}
	uip = fsr[ui];
	lip = fsr[li];
	for (i=0; i<4; i++) {
		block[i] = (unsigned char)((uip >> (i*8)) & 0xff);
		block[i+4] = (unsigned char)((lip >> (i*8)) & 0xff);
	}
	
	block_cipher(RANDKEY, block, 0);
	
	retval = block[3];
	for (i=2; i >= 0; i--)
		retval = (retval << 8) + (unsigned long)(block[i] & 0xFF);
	
	uip = block[7];
	for (i=6; i>=4; i--)
		uip = (uip << 8) + (unsigned long)(block[i] & 0xff);
	
	fsr[ui] ^= uip;
	
	li--;
	ui--;
	if (li == -1)
		li = UPPER_INDEX;
	else if (ui == -1)
		ui = UPPER_INDEX;
	
	
	return retval;
}

