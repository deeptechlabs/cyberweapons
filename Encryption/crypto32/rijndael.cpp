// rijndael.cpp - modified by Wei Dai from Brian Gladman's rijndael.c

/* This is an independent implementation of the encryption algorithm:	*/
/*																		*/
/*		   RIJNDAEL by Joan Daemen and Vincent Rijmen					*/
/*																		*/
/* which is a candidate algorithm in the Advanced Encryption Standard	*/
/* programme of the US National Institute of Standards and Technology.	*/
/*																		*/
/* Copyright in this implementation is held by Dr B R Gladman but I 	*/
/* hereby give permission for its free direct or derivative use subject */
/* to acknowledgment of its origin and compliance with any conditions	*/
/* that the originators of the algorithm place on its exploitation. 	*/
/*																		*/
/* Dr Brian Gladman (gladman@seven77.demon.co.uk) 14th January 1999 	*/

#include "pch.h"
#include "rijndael.h"

NAMESPACE_BEGIN(CryptoPP)

/* initialise the key schedule from the user supplied key	*/

#define ls_box(x)							 \
	((word32)sbx_tab[GETBYTE(x, 0)] <<	0) ^	\
	((word32)sbx_tab[GETBYTE(x, 1)] <<	8) ^	\
	((word32)sbx_tab[GETBYTE(x, 2)] << 16) ^	\
	((word32)sbx_tab[GETBYTE(x, 3)] << 24)

Rijndael::Rijndael(const byte *userKey, unsigned int keylen)
	: k_len(keylen/4), key(k_len*5 + 24)
{
	assert(keylen == KeyLength(keylen));

	word32 t;
	int i;

	GetUserKeyLittleEndian(key.ptr, k_len, userKey, keylen);

	switch(k_len)
	{
		case 4: t = key[3];
				for(i = 0; i < 10; ++i)
				{
					t = rotrFixed(t, 8);
					t = ls_box(t) ^ rco_tab[i];
					key[4 * i + 4] = t ^= key[4 * i];
					key[4 * i + 5] = t ^= key[4 * i + 1];
					key[4 * i + 6] = t ^= key[4 * i + 2];
					key[4 * i + 7] = t ^= key[4 * i + 3];
				}
				break;

		case 6: t = key[5];
				for(i = 0; i < 8; ++i)
				{
					t = rotrFixed(t,  8);
					t = ls_box(t) ^ rco_tab[i];
					key[6 * i + 6] = t ^= key[6 * i];
					key[6 * i + 7] = t ^= key[6 * i + 1];
					key[6 * i + 8] = t ^= key[6 * i + 2];
					key[6 * i + 9] = t ^= key[6 * i + 3];
					key[6 * i + 10] = t ^= key[6 * i + 4];
					key[6 * i + 11] = t ^= key[6 * i + 5];
				}
				break;

		case 8: t = key[7];
				for(i = 0; i < 7; ++i)
				{
					t = rotrFixed(t,  8);
					t = ls_box(t) ^ rco_tab[i];
					key[8 * i + 8] = t ^= key[8 * i];
					key[8 * i + 9] = t ^= key[8 * i + 1];
					key[8 * i + 10] = t ^= key[8 * i + 2];
					key[8 * i + 11] = t ^= key[8 * i + 3];
					key[8 * i + 12] = t = key[8 * i + 4] ^ ls_box(t);				\
					key[8 * i + 13] = t ^= key[8 * i + 5];
					key[8 * i + 14] = t ^= key[8 * i + 6];
					key[8 * i + 15] = t ^= key[8 * i + 7];
				}
				break;
	}
}

/* encrypt a block of text	*/

#define f_rn(bo, bi, n, k)							\
	bo[n] =  ft_tab[0][GETBYTE(bi[n],0)] ^			   \
			 ft_tab[1][GETBYTE(bi[(n + 1) & 3],1)] ^   \
			 ft_tab[2][GETBYTE(bi[(n + 2) & 3],2)] ^   \
			 ft_tab[3][GETBYTE(bi[(n + 3) & 3],3)] ^ *(k + n)

#define f_rl(bo, bi, n, k)										\
	bo[n] = (word32)sbx_tab[GETBYTE(bi[n],0)] ^ 				   \
		rotlFixed(((word32)sbx_tab[GETBYTE(bi[(n + 1) & 3],1)]),  8) ^	\
		rotlFixed(((word32)sbx_tab[GETBYTE(bi[(n + 2) & 3],2)]), 16) ^	\
		rotlFixed(((word32)sbx_tab[GETBYTE(bi[(n + 3) & 3],3)]), 24) ^ *(k + n)

#define f_nround(bo, bi, k) \
	f_rn(bo, bi, 0, k); 	\
	f_rn(bo, bi, 1, k); 	\
	f_rn(bo, bi, 2, k); 	\
	f_rn(bo, bi, 3, k); 	\
	k += 4

#define f_lround(bo, bi, k) \
	f_rl(bo, bi, 0, k); 	\
	f_rl(bo, bi, 1, k); 	\
	f_rl(bo, bi, 2, k); 	\
	f_rl(bo, bi, 3, k)

void RijndaelEncryption::ProcessBlock(const byte *inBlock, byte *outBlock) const
{
	word32 b0[4], b1[4];

	GetBlockLittleEndian(inBlock, b0[0], b0[1], b0[2], b0[3]);

	b0[0] ^= key[0];
	b0[1] ^= key[1];
	b0[2] ^= key[2];
	b0[3] ^= key[3];

	const word32 *kp = key + 4;

	if(k_len > 6)
	{
		f_nround(b1, b0, kp); f_nround(b0, b1, kp);
	}

	if(k_len > 4)
	{
		f_nround(b1, b0, kp); f_nround(b0, b1, kp);
	}

	f_nround(b1, b0, kp); f_nround(b0, b1, kp);
	f_nround(b1, b0, kp); f_nround(b0, b1, kp);
	f_nround(b1, b0, kp); f_nround(b0, b1, kp);
	f_nround(b1, b0, kp); f_nround(b0, b1, kp);
	f_nround(b1, b0, kp); f_lround(b0, b1, kp);

	PutBlockLittleEndian(outBlock, b0[0], b0[1], b0[2], b0[3]);
}

// convert encryption key schedule to decryption key schedule

#define star_x(x) (((x) & 0x7f7f7f7f) << 1) ^ ((((x) & 0x80808080) >> 7) * 0x1b)

#define imix_col(y,x)		\
	u	= star_x(x);		\
	v	= star_x(u);		\
	w	= star_x(v);		\
	t	= w ^ (x);			\
   (y)	= u ^ v ^ w;		\
   (y) ^= rotrFixed(u ^ t,	8) ^ \
		  rotrFixed(v ^ t, 16) ^ \
		  rotrFixed(t,24)

RijndaelDecryption::RijndaelDecryption(const byte *userKey, unsigned int keylength)
	: Rijndael(userKey, keylength)
{
	word32 t, u, v, w;

	int i;
	for(i = 4; i < 4 * k_len + 24; ++i)
	{
		imix_col(key[i], key[i]);
	}
}

/* decrypt a block of text	*/

#define i_rn(bo, bi, n, k)							\
	bo[n] =  it_tab[0][GETBYTE(bi[n],0)] ^			   \
			 it_tab[1][GETBYTE(bi[(n + 3) & 3],1)] ^   \
			 it_tab[2][GETBYTE(bi[(n + 2) & 3],2)] ^   \
			 it_tab[3][GETBYTE(bi[(n + 1) & 3],3)] ^ *(k + n)

#define i_rl(bo, bi, n, k)										\
	bo[n] = (word32)isb_tab[GETBYTE(bi[n],0)] ^ 				   \
		rotlFixed(((word32)isb_tab[GETBYTE(bi[(n + 3) & 3],1)]),  8) ^	\
		rotlFixed(((word32)isb_tab[GETBYTE(bi[(n + 2) & 3],2)]), 16) ^	\
		rotlFixed(((word32)isb_tab[GETBYTE(bi[(n + 1) & 3],3)]), 24) ^ *(k + n)

#define i_nround(bo, bi, k) \
	i_rn(bo, bi, 0, k); 	\
	i_rn(bo, bi, 1, k); 	\
	i_rn(bo, bi, 2, k); 	\
	i_rn(bo, bi, 3, k); 	\
	k -= 4

#define i_lround(bo, bi, k) \
	i_rl(bo, bi, 0, k); 	\
	i_rl(bo, bi, 1, k); 	\
	i_rl(bo, bi, 2, k); 	\
	i_rl(bo, bi, 3, k)

void RijndaelDecryption::ProcessBlock(const byte *inBlock, byte *outBlock) const
{
	word32	b0[4], b1[4];

	GetBlockLittleEndian(inBlock, b0[0], b0[1], b0[2], b0[3]);

	b0[0] ^= key[4 * k_len + 24];
	b0[1] ^= key[4 * k_len + 25];
	b0[2] ^= key[4 * k_len + 26];
	b0[3] ^= key[4 * k_len + 27];

	const word32 *kp = key + 4 * (k_len + 5);

	if(k_len > 6)
	{
		i_nround(b1, b0, kp); i_nround(b0, b1, kp);
	}

	if(k_len > 4)
	{
		i_nround(b1, b0, kp); i_nround(b0, b1, kp);
	}

	i_nround(b1, b0, kp); i_nround(b0, b1, kp);
	i_nround(b1, b0, kp); i_nround(b0, b1, kp);
	i_nround(b1, b0, kp); i_nround(b0, b1, kp);
	i_nround(b1, b0, kp); i_nround(b0, b1, kp);
	i_nround(b1, b0, kp); i_lround(b0, b1, kp);

	PutBlockLittleEndian(outBlock, b0[0], b0[1], b0[2], b0[3]);
}

NAMESPACE_END
