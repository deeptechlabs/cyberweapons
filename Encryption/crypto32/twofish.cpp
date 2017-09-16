// twofish.cpp - modified by Wei Dai from Brian Gladman's twofish.c

/* This is an independent implementation of the encryption algorithm:	*/
/*																		*/
/*		   Twofish by Bruce Schneier and colleagues 					*/
/*																		*/
/* which is a candidate algorithm in the Advanced Encryption Standard	*/
/* programme of the US National Institute of Standards and Technology.	*/
/*																		*/
/* Copyright in this implementation is held by Dr B R Gladman but I 	*/
/* hereby give permission for its free direct or derivative use subject */
/* to acknowledgment of its origin and compliance with any conditions	*/
/* that the originators of the algorithm place on its exploitation.		*/
/*																		*/
/* My thanks to Doug Whiting and Niels Ferguson for comments that led	*/
/* to improvements in this implementation.								*/
/*																		*/
/* Dr Brian Gladman (gladman@seven77.demon.co.uk) 14th January 1999 	*/

#include "pch.h"
#include "twofish.h"

NAMESPACE_BEGIN(CryptoPP)

ANONYMOUS_NAMESPACE_BEGIN

/* The (12,8) Reed Soloman code has the generator polynomial

  g(x) = x^4 + (a + 1/a) * x^3 + a * x^2 + (a + 1/a) * x + 1

where the coefficients are in the finite field GF(2^8) with a
modular polynomial a^8 + a^6 + a^3 + a^2 + 1. To generate the
remainder we have to start with a 12th order polynomial with our
eight input bytes as the coefficients of the 4th to 11th terms. 
That is:

  m[7] * x^11 + m[6] * x^10 ... + m[0] * x^4 + 0 * x^3 +... + 0
  
We then multiply the generator polynomial by m[7] * x^7 and subtract
it - xor in GF(2^8) - from the above to eliminate the x^7 term (the 
artihmetic on the coefficients is done in GF(2^8). We then multiply 
the generator polynomial by x^6 * coeff(x^10) and use this to remove
the x^10 term. We carry on in this way until the x^4 term is removed
so that we are left with:

  r[3] * x^3 + r[2] * x^2 + r[1] 8 x^1 + r[0]

which give the resulting 4 bytes of the remainder. This is equivalent 
to the matrix multiplication in the Twofish description but much faster 
to implement.

*/

static const word32 G_MOD = 0x0000014d;

static word32 mds_rem(word32 p0, word32 p1)
{
	word32	i, t, u;

	for(i = 0; i < 8; ++i)
	{
		t = p1 >> 24;	// get most significant coefficient
		
		p1 = (p1 << 8) | (p0 >> 24); p0 <<= 8;	// shift others up
			
		// multiply t by a (the primitive element - i.e. left shift)

		u = (t << 1); 
		
		if(t & 0x80)			// subtract modular polynomial on overflow
		
			u ^= G_MOD; 

		p1 ^= t ^ (u << 16);	// remove t * (a * x^2 + 1)  

		u ^= (t >> 1);			// form u = a * t + t / a = t * (a + 1 / a); 
		
		if(t & 0x01)			// add the modular polynomial on underflow
		
			u ^= G_MOD >> 1;

		p1 ^= (u << 24) | (u << 8); // remove t * (a + 1/a) * (x^3 + x)
	}

	return p1;
}

NAMESPACE_END

#define q(n,x)	q_tab[n][x]

#define mds(n,x)	m_tab[n][x]

word32 Twofish::h_fun(const word32 x, const word32 key[])
{
	word32 b0, b1, b2, b3;

	b0 = GETBYTE(x, 0); b1 = GETBYTE(x, 1); b2 = GETBYTE(x, 2); b3 = GETBYTE(x, 3);

	switch(k_len)
	{
	case 4: b0 = q(1, b0) ^ GETBYTE(key[6],0);
			b1 = q(0, b1) ^ GETBYTE(key[6],1);
			b2 = q(0, b2) ^ GETBYTE(key[6],2);
			b3 = q(1, b3) ^ GETBYTE(key[6],3);
	case 3: b0 = q(1, b0) ^ GETBYTE(key[4],0);
			b1 = q(1, b1) ^ GETBYTE(key[4],1);
			b2 = q(0, b2) ^ GETBYTE(key[4],2);
			b3 = q(0, b3) ^ GETBYTE(key[4],3);
	case 2: b0 = q(0,q(0,b0) ^ GETBYTE(key[2],0)) ^ GETBYTE(key[0],0);
			b1 = q(0,q(1,b1) ^ GETBYTE(key[2],1)) ^ GETBYTE(key[0],1);
			b2 = q(1,q(0,b2) ^ GETBYTE(key[2],2)) ^ GETBYTE(key[0],2);
			b3 = q(1,q(1,b3) ^ GETBYTE(key[2],3)) ^ GETBYTE(key[0],3);
	}

	return	mds(0, b0) ^ mds(1, b1) ^ mds(2, b2) ^ mds(3, b3);
}

#define q20(x)	q(0,q(0,x) ^ GETBYTE(key[1],0)) ^ GETBYTE(key[0],0)
#define q21(x)	q(0,q(1,x) ^ GETBYTE(key[1],1)) ^ GETBYTE(key[0],1)
#define q22(x)	q(1,q(0,x) ^ GETBYTE(key[1],2)) ^ GETBYTE(key[0],2)
#define q23(x)	q(1,q(1,x) ^ GETBYTE(key[1],3)) ^ GETBYTE(key[0],3)

#define q30(x)	q(0,q(0,q(1, x) ^ GETBYTE(key[2],0)) ^ GETBYTE(key[1],0)) ^ GETBYTE(key[0],0)
#define q31(x)	q(0,q(1,q(1, x) ^ GETBYTE(key[2],1)) ^ GETBYTE(key[1],1)) ^ GETBYTE(key[0],1)
#define q32(x)	q(1,q(0,q(0, x) ^ GETBYTE(key[2],2)) ^ GETBYTE(key[1],2)) ^ GETBYTE(key[0],2)
#define q33(x)	q(1,q(1,q(0, x) ^ GETBYTE(key[2],3)) ^ GETBYTE(key[1],3)) ^ GETBYTE(key[0],3)

#define q40(x)	q(0,q(0,q(1, q(1, x) ^ GETBYTE(key[3],0)) ^ GETBYTE(key[2],0)) ^ GETBYTE(key[1],0)) ^ GETBYTE(key[0],0)
#define q41(x)	q(0,q(1,q(1, q(0, x) ^ GETBYTE(key[3],1)) ^ GETBYTE(key[2],1)) ^ GETBYTE(key[1],1)) ^ GETBYTE(key[0],1)
#define q42(x)	q(1,q(0,q(0, q(0, x) ^ GETBYTE(key[3],2)) ^ GETBYTE(key[2],2)) ^ GETBYTE(key[1],2)) ^ GETBYTE(key[0],2)
#define q43(x)	q(1,q(1,q(0, q(1, x) ^ GETBYTE(key[3],3)) ^ GETBYTE(key[2],3)) ^ GETBYTE(key[1],3)) ^ GETBYTE(key[0],3)

void Twofish::gen_mk_tab(word32 key[])
{	word32	i;
	byte  by;

	switch(k_len)
	{
	case 2: for(i = 0; i < 256; ++i)
			{
				by = (byte)i;
				mk_tab[0][i] = mds(0, q20(by)); mk_tab[1][i] = mds(1, q21(by));
				mk_tab[2][i] = mds(2, q22(by)); mk_tab[3][i] = mds(3, q23(by));
			}
			break;
	
	case 3: for(i = 0; i < 256; ++i)
			{
				by = (byte)i;
				mk_tab[0][i] = mds(0, q30(by)); mk_tab[1][i] = mds(1, q31(by));
				mk_tab[2][i] = mds(2, q32(by)); mk_tab[3][i] = mds(3, q33(by));
			}
			break;
	
	case 4: for(i = 0; i < 256; ++i)
			{
				by = (byte)i;
				mk_tab[0][i] = mds(0, q40(by)); mk_tab[1][i] = mds(1, q41(by));
				mk_tab[2][i] = mds(2, q42(by)); mk_tab[3][i] = mds(3, q43(by));
			}
	}
}

#	 define g0_fun(x) ( mk_tab[0][GETBYTE(x,0)] ^ mk_tab[1][GETBYTE(x,1)] \
					  ^ mk_tab[2][GETBYTE(x,2)] ^ mk_tab[3][GETBYTE(x,3)] )
#	 define g1_fun(x) ( mk_tab[0][GETBYTE(x,3)] ^ mk_tab[1][GETBYTE(x,0)] \
					  ^ mk_tab[2][GETBYTE(x,1)] ^ mk_tab[3][GETBYTE(x,2)] )

/* initialise the key schedule from the user supplied key	*/

Twofish::Twofish(const byte *userKey, unsigned int keylength)
	: k_len(keylength/8), l_key(40), mk_tab(4)
{
	assert(keylength == KeyLength(keylength));

	SecBlock<word32> in_key(k_len*2);
	GetUserKeyLittleEndian(in_key.ptr, k_len*2, userKey, keylength);

	unsigned int i;
	for(i = 0; i < 40; i += 2)
	{
		word32 a = 0x01010101 * i;
		word32 b = a + 0x01010101;
		a = h_fun(a, in_key);
		b = rotlFixed(h_fun(b, in_key+1), 8);
		l_key[i] = a + b;
		l_key[i + 1] = rotlFixed(a + 2 * b, 9);
	}

	SecBlock<word32> s_key(k_len);
	for(i = 0; i < k_len; ++i)
		s_key[k_len - i - 1] = mds_rem(in_key[2*i], in_key[2*i+1]);
	gen_mk_tab(s_key);
}

/* encrypt a block of text	*/

#define f_rnd(i)													\
	t1 = g1_fun(blk[1]); t0 = g0_fun(blk[0]);						\
	blk[2] = rotrFixed(blk[2] ^ (t0 + t1 + l_key[4 * (i) + 8]), 1); 	 \
	blk[3] = rotlFixed(blk[3], 1) ^ (t0 + 2 * t1 + l_key[4 * (i) + 9]);  \
	t1 = g1_fun(blk[3]); t0 = g0_fun(blk[2]);						\
	blk[0] = rotrFixed(blk[0] ^ (t0 + t1 + l_key[4 * (i) + 10]), 1);	 \
	blk[1] = rotlFixed(blk[1], 1) ^ (t0 + 2 * t1 + l_key[4 * (i) + 11])

void TwofishEncryption::ProcessBlock(const byte *inBlock, byte *outBlock) const
{
	word32	t0, t1, blk[4];

	GetBlockLittleEndian(inBlock, blk[0], blk[1], blk[2], blk[3]);

	blk[0] ^= l_key[0];
	blk[1] ^= l_key[1];
	blk[2] ^= l_key[2];
	blk[3] ^= l_key[3];

	f_rnd(0); f_rnd(1); f_rnd(2); f_rnd(3);
	f_rnd(4); f_rnd(5); f_rnd(6); f_rnd(7);

	blk[2] ^= l_key[4];
	blk[3] ^= l_key[5];
	blk[0] ^= l_key[6];
	blk[1] ^= l_key[7]; 

	PutBlockLittleEndian(outBlock, blk[2], blk[3], blk[0], blk[1]);
}

/* decrypt a block of text	*/

#define i_rnd(i)														\
		t1 = g1_fun(blk[1]); t0 = g0_fun(blk[0]);						\
		blk[2] = rotlFixed(blk[2], 1) ^ (t0 + t1 + l_key[4 * (i) + 10]);	 \
		blk[3] = rotrFixed(blk[3] ^ (t0 + 2 * t1 + l_key[4 * (i) + 11]), 1); \
		t1 = g1_fun(blk[3]); t0 = g0_fun(blk[2]);						\
		blk[0] = rotlFixed(blk[0], 1) ^ (t0 + t1 + l_key[4 * (i) +	8]);	 \
		blk[1] = rotrFixed(blk[1] ^ (t0 + 2 * t1 + l_key[4 * (i) +	9]), 1)

void TwofishDecryption::ProcessBlock(const byte *inBlock, byte *outBlock) const
{
	word32 t0, t1, blk[4];

	GetBlockLittleEndian(inBlock, blk[0], blk[1], blk[2], blk[3]);

	blk[0] ^= l_key[4];
	blk[1] ^= l_key[5];
	blk[2] ^= l_key[6];
	blk[3] ^= l_key[7];

	i_rnd(7); i_rnd(6); i_rnd(5); i_rnd(4);
	i_rnd(3); i_rnd(2); i_rnd(1); i_rnd(0);

	blk[2] ^= l_key[0];
	blk[3] ^= l_key[1];
	blk[0] ^= l_key[2];
	blk[1] ^= l_key[3]; 

	PutBlockLittleEndian(outBlock, blk[2], blk[3], blk[0], blk[1]);
}

NAMESPACE_END
