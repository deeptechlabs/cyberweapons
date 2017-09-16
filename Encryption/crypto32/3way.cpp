// 3way.cpp - modifed by Wei Dai from Joan Daemen's 3way.c

#include "pch.h"
#include "3way.h"

NAMESPACE_BEGIN(CryptoPP)

static const word32 START_E = 0x0b0b; // round constant of first encryption round
static const word32 START_D = 0xb1b1; // round constant of first decryption round

static inline word32 reverseBits(word32 a)
{
	a = ((a & 0xAAAAAAAAL) >> 1) | ((a & 0x55555555L) << 1);
	a = ((a & 0xCCCCCCCCL) >> 2) | ((a & 0x33333333L) << 2);
	return ((a & 0xF0F0F0F0L) >> 4) | ((a & 0x0F0F0F0FL) << 4);
}

#define mu(a0, a1, a2)				\
{									\
	a1 = reverseBits(a1);			\
	word32 t = reverseBits(a0);		\
	a0 = reverseBits(a2);			\
	a2 = t;							\
}

#define pi_gamma_pi(a0, a1, a2)		\
{									\
	word32 b0, b2;					\
	b2 = rotlFixed(a2, 1U);				\
	b0 = rotlFixed(a0, 22U);				\
	a0 = rotlFixed(b0 ^ (a1|(~b2)), 1U);	\
	a2 = rotlFixed(b2 ^ (b0|(~a1)), 22U);\
	a1 ^= (b2|(~b0));				\
}

// thanks to Paulo Barreto for this optimized theta()
#define theta(a0, a1, a2)									\
{ 															\
	word32 b0, b1, c; 										\
	c = a0 ^ a1 ^ a2; 										\
	c = rotlFixed(c, 16U) ^ rotlFixed(c, 8U);				\
	b0 = (a0 << 24) ^ (a2 >> 8) ^ (a1 << 8) ^ (a0 >> 24); 	\
	b1 = (a1 << 24) ^ (a0 >> 8) ^ (a2 << 8) ^ (a1 >> 24); 	\
	a0 ^= c ^ b0; 											\
	a1 ^= c ^ b1; 											\
	a2 ^= c ^ (b0 >> 16) ^ (b1 << 16); 						\
}															

#define rho(a0, a1, a2)			\
{								\
	theta(a0, a1, a2);			\
	pi_gamma_pi(a0, a1, a2);	\
}											

static void GenerateRoundConstants(word32 strt, word32 *rtab, unsigned int rounds)
{
	for(unsigned i=0; i<=rounds; i++)
	{
		rtab[i] = strt;
		strt <<= 1;
		if (strt&0x10000) strt ^= 0x11011;
	}
}

ThreeWayEncryption::ThreeWayEncryption(const byte *uk, unsigned int keylength, unsigned int rounds)
	: rounds(rounds), rc(rounds+1)
{
	assert(keylength == 0 || keylength == KEYLENGTH);
	GenerateRoundConstants(START_E, rc, rounds);
	for (int i=0; i<3; i++)
		k[i] = (word32)uk[4*i+3] | ((word32)uk[4*i+2]<<8) | ((word32)uk[4*i+1]<<16) | ((word32)uk[4*i]<<24);
}

ThreeWayEncryption::~ThreeWayEncryption()
{
	k[0]=k[1]=k[2]=0;
}

void ThreeWayEncryption::ProcessBlock(const byte *in, byte * out) const
{
	word32 a0, a1, a2;

#ifdef IS_LITTLE_ENDIAN
	a0 = byteReverse(*(word32 *)in);
	a1 = byteReverse(*(word32 *)(in+4));
	a2 = byteReverse(*(word32 *)(in+8));
#else
	a0 = *(word32 *)in;
	a1 = *(word32 *)(in+4);
	a2 = *(word32 *)(in+8);
#endif

	for(unsigned i=0; i<rounds; i++)
	{
		a0 ^= k[0] ^ (rc[i]<<16);
		a1 ^= k[1];
		a2 ^= k[2] ^ rc[i];
		rho(a0, a1, a2);
	}
	a0 ^= k[0] ^ (rc[rounds]<<16);
	a1 ^= k[1];
	a2 ^= k[2] ^ rc[rounds];
	theta(a0, a1, a2);

#ifdef IS_LITTLE_ENDIAN
	*(word32 *)out = byteReverse(a0);
	*(word32 *)(out+4) = byteReverse(a1);
	*(word32 *)(out+8) = byteReverse(a2);
#else
	*(word32 *)out = a0;
	*(word32 *)(out+4) = a1;
	*(word32 *)(out+8) = a2;
#endif
}

ThreeWayDecryption::ThreeWayDecryption(const byte *uk, unsigned int keylength, unsigned int rounds)
	: rounds(rounds), rc(rounds+1)
{
	assert(keylength == 0 || keylength == KEYLENGTH);
	GenerateRoundConstants(START_D, rc, rounds);
	for (int i=0; i<3; i++)
		k[i] = (word32)uk[4*i+3] | ((word32)uk[4*i+2]<<8) | ((word32)uk[4*i+1]<<16) | ((word32)uk[4*i]<<24);
	theta(k[0], k[1], k[2]);
	mu(k[0], k[1], k[2]);
	k[0] = byteReverse(k[0]);
	k[1] = byteReverse(k[1]);
	k[2] = byteReverse(k[2]);
}

ThreeWayDecryption::~ThreeWayDecryption()
{
	k[0]=k[1]=k[2]=0;
}

void ThreeWayDecryption::ProcessBlock(const byte *in, byte * out) const
{
	word32 a0, a1, a2;

#ifndef IS_LITTLE_ENDIAN
	a0 = byteReverse(*(word32 *)in);
	a1 = byteReverse(*(word32 *)(in+4));
	a2 = byteReverse(*(word32 *)(in+8));
#else
	a0 = *(word32 *)in;
	a1 = *(word32 *)(in+4);
	a2 = *(word32 *)(in+8);
#endif

	mu(a0, a1, a2);
	for(unsigned i=0; i<rounds; i++)
	{
		a0 ^= k[0] ^ (rc[i]<<16);
		a1 ^= k[1];
		a2 ^= k[2] ^ rc[i];
		rho(a0, a1, a2);
	}
	a0 ^= k[0] ^ (rc[rounds]<<16);
	a1 ^= k[1];
	a2 ^= k[2] ^ rc[rounds];
	theta(a0, a1, a2);
	mu(a0, a1, a2);

#ifndef IS_LITTLE_ENDIAN
	*(word32 *)out = byteReverse(a0);
	*(word32 *)(out+4) = byteReverse(a1);
	*(word32 *)(out+8) = byteReverse(a2);
#else
	*(word32 *)out = a0;
	*(word32 *)(out+4) = a1;
	*(word32 *)(out+8) = a2;
#endif
}

NAMESPACE_END
