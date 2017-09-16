/*****************************************************************************/
/*                        IDEA Encryption Algorithm                          */
/*****************************************************************************/
/*                                                                           */
/*   IDEA (International Data Encryption Algorithm) is a block encryption    */
/*   algorithm whose development results from a co-operation between the     */
/*   Swiss Federal Institute of Technology Zurich (ETHZ) and Ascom Tech Ltd. */
/*   IDEA encrypts or decrypts 64-bit data blocks, using symmetric 128-bit   */
/*   keys. The 128-bit keys are furthermore expanded to 52 16-bit subkeys.   */
/*                                                                           */
/*   For detailed technical information on IDEA contact:                     */
/*                                                                           */
/*          Ascom Systec Ltd.              E-Mail: IDEA@ASCOM.CH             */
/*          Gewerbepark                    http://WWW.ASCOM.COM/INFOSEC      */
/*          CH-5506 Maegenwil                                                */
/*          Switzerland                                                      */
/*                                                                           */
/*   Patent rights of Ascom Systec Ltd. granted in Europe, Japan and the US. */
/*   All other rights reserved.                                              */
/*                                                                           */
/*   For detailed patent information on IDEA contact:                        */
/*                                                                           */
/*          Ascom Systec Ltd.              E-Mail: IDEA@ASCOM.CH             */
/*          Gewerbepark                    http://WWW.ASCOM.COM/INFOSEC      */
/*          CH-5506 Maegenwil                                                */
/*          Switzerland                                                      */
/*                                                                           */
/*****************************************************************************/
/*                                                                           */
/*   Author:    Alain Beuchat/Daniel Zimmermann                              */
/*   Release:   2.1                                                          */
/*                                                                           */
/*****************************************************************************/
/*
 * File Name:		ideaplus.c
 *
 * Compile Options:	- none
 *
 * Routines:
 * _VOID_ idea_encrypt_subkeys(idea_key_t,idea_subkeys_t)
 *	_VOID_ idea_decrypt_subkeys(idea_subkeys_t,idea_subkeys_t)
 *	_VOID_ idea_cipher(idea_block_t,idea_block_t,idea_subkeys_t)
 *
 * Description:
 *	IDEA 64-bit block cipher algorithm
 *	idea_encrypt_subkeys: computes the encryption IDEA subkeys
 *	idea_decrypt_subkeys: computes the decryption IDEA subkeys
 *	idea_cipher: IDEA block cipher
 *
 */

#include "c_fct.h"
#include "ideaplus.h"

#define LSW16(y) ((y) & 0xffff)			 /* low significant 16-bit */
#define MSW16(y) ((y >> 16) & 0xffff)		 /* most significant 16-bit */
#define MUL_MOD  (uint32)(((uint32)1 << 16) | 1) /* 2**16 + 1 */

/*
 * Multiplication modulo 2**16 + 1
 */
static uint16 mul
C_ARG_2( uint16,x, uint16,y)
{
   uint16 t16;
   uint32 t32;

   x =  LSW16(x - 1);
   t16 = LSW16(y - 1);
   t32 = (uint32) x * t16 + x + t16 + 1;
   x = LSW16( t32 );
   t16 = MSW16( t32 );
   x = (x - t16) + (x <=t16);
   return x;

} /* mul */

/*
 * Compute multiplicative inverse of x by Euclid's GCD algorithm.
 */
static uint16 mul_inv
C_ARG_1(uint16,x)
{
	int32 n1 = MUL_MOD;
	int32 n2 = (int32)x;
	int32 b1 = 0;
	int32 b2 = 1;
	int32 q, r, t;

	if (x <= 1) return x;
	while (1) {
		r = n1 % n2;
		q = n1 / n2;
		if (!r) {
			if (b2 < 0) b2 += MUL_MOD;
			return LSW16(b2);
		}
		else {
			n1 = n2;
			n2 = r;
			t  = b2;
			b2 = b1 - q * b2;
			b1 = t;
		}
	}
} /* mul_inv */

/*
 * Computes IDEA encryption subkeys.
 */
_VOID_ idea_encrypt_subkeys
C_ARG_2( idea_key_t,key, idea_subkeys_t,subkeys)
{
	int i;

	for (i=0;i<8;i++) subkeys[i] = key[i];
	for (;i<IDEA_SK_NUM;i++)
		subkeys[i] = LSW16((subkeys[(i+1) % 0x8 ? i-7 : i-15] << 9) |
			(subkeys[(i+2) % 0x8 < 2 ? i-14 : i-6] >> 7));
} /* idea_encrypt_subkeys */

/*
 * Computes IDEA decryption subkeys from encryption subkeys.
 */
_VOID_ idea_decrypt_subkeys
C_ARG_2( idea_subkeys_t,encrypt_subkeys, idea_subkeys_t,decrypt_subkeys)
{
	uint16 *pen = (uint16*)encrypt_subkeys;
	uint16 *pde = (uint16*)decrypt_subkeys;
	idea_subkeys_t t;
	uint16 *pt = (uint16*)t;
	int i;

	t[6 * IDEA_ROUNDS] = mul_inv(*pen++);
	t[6 * IDEA_ROUNDS + 1] = LSW16(-*pen++);
	t[6 * IDEA_ROUNDS + 2] = LSW16(-*pen++);
	t[6 * IDEA_ROUNDS + 3] = mul_inv(*pen++);
	for (i=6*(IDEA_ROUNDS-1);i>=0;i-=6) {
		t[i + 4] = *pen++;
		t[i + 5] = *pen++;
		t[i] = mul_inv(*pen++);
		if (i) {
			t[i + 2] = LSW16(-*pen++);
			t[i + 1] = LSW16(-*pen++);
		}
		else {
			t[1] = LSW16(-*pen++);
			t[2] = LSW16(-*pen++);
		}
		t[i + 3] = mul_inv(*pen++);
	}
	for (i=0;i<IDEA_SK_NUM;i++) {
		*pde++ = *pt;
		*pt++ = 0;
	}
} /* idea_decrypt_subkey */


/*
 * IDEA encryption/decryption algorithm.
 * Note: block_in and block_out can be the same block.
 */
_VOID_ idea_cipher
C_ARG_3(idea_block_t,block_in, idea_block_t,block_out, idea_subkeys_t,key)
{
	uint16 *pin = (uint16*)block_in;
	uint16 *pout = (uint16*)block_out;
	uint16 *pk = (uint16*)key;
	uint16 word1, word2, word3, word4;
	uint16 t1, t2;
	int i;

	word1 = *pin++;
	word2 = *pin++;
	word3 = *pin++;
	word4 = *pin;

	for (i=IDEA_ROUNDS;i>0;i--) {
		word1 = mul(word1,*pk++);
		word2 = LSW16(word2 + *pk++);
		word3 = LSW16(word3 + *pk++);
		word4 = mul(word4,*pk++);

		t2 = word1 ^ word3;
		t2 = mul(t2,*pk++);
		t1 = LSW16(t2 + (word2 ^ word4));
		t1 = mul(t1,*pk++);
		t2 = LSW16(t1 + t2);

		word1 ^= t1;
		word4 ^= t2;

		t2 ^= word2;
		word2 = word3 ^ t1;
		word3 = t2;
	}

	word1 = mul(word1,*pk++);
	*pout++ = word1;
	*pout++ = LSW16(word3 + *pk++);
	*pout++ = LSW16(word2 + *pk++);
	word4 = mul(word4,*pk);
	*pout = word4;
} /* idea_cipher */
