// tiger.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "tiger.h"

#ifdef WORD64_AVAILABLE

NAMESPACE_BEGIN(CryptoPP)

Tiger::Tiger(unsigned int digestSize)
	: IteratedHash<word64>(DATASIZE, DIGESTSIZE),
	  digestSize(digestSize)
{
	Init();
}

void Tiger::Init()
{
	countLo = countHi = 0;

	digest[0] = W64LIT(0x0123456789ABCDEF);
	digest[1] = W64LIT(0xFEDCBA9876543210);
	digest[2] = W64LIT(0xF096A5B4C3B2E187);
}

void Tiger::HashBlock(const word64 *input)
{
#ifdef IS_LITTLE_ENDIAN
	Transform(digest, input);
#else
	byteReverse(data.ptr, input, (unsigned int)DATASIZE);
	Transform(digest, data);
#endif
}

void Tiger::Final(byte *hash)
{
	PadLastBlock(56, 0x01);
	CorrectEndianess(data, data, 56);

	data[7] = (word64(countHi)<<32) + countLo;

	Transform(digest, data);
	CorrectEndianess(digest, digest, DIGESTSIZE);
	memcpy(hash, digest, digestSize);

	Init();		// reinit for next use
}

#define t1 (table)
#define t2 (table+256)
#define t3 (table+256*2)
#define t4 (table+256*3)

#define round(a,b,c,x,mul) \
	c ^= x; \
	a -= t1[GETBYTE(c,0)] ^ t2[GETBYTE(c,2)] ^ t3[GETBYTE(c,4)] ^ t4[GETBYTE(c,6)]; \
	b += t4[GETBYTE(c,1)] ^ t3[GETBYTE(c,3)] ^ t2[GETBYTE(c,5)] ^ t1[GETBYTE(c,7)]; \
	b *= mul

#define pass(a,b,c,mul,X) \
	round(a,b,c,X[0],mul); \
	round(b,c,a,X[1],mul); \
	round(c,a,b,X[2],mul); \
	round(a,b,c,X[3],mul); \
	round(b,c,a,X[4],mul); \
	round(c,a,b,X[5],mul); \
	round(a,b,c,X[6],mul); \
	round(b,c,a,X[7],mul)

#define key_schedule(Y,X) \
	Y[0] = X[0] - (X[7]^W64LIT(0xA5A5A5A5A5A5A5A5)); \
	Y[1] = X[1] ^ Y[0]; \
	Y[2] = X[2] + Y[1]; \
	Y[3] = X[3] - (Y[2] ^ ((~Y[1])<<19)); \
	Y[4] = X[4] ^ Y[3]; \
	Y[5] = X[5] + Y[4]; \
	Y[6] = X[6] - (Y[5] ^ ((~Y[4])>>23)); \
	Y[7] = X[7] ^ Y[6]; \
	Y[0] += Y[7]; \
	Y[1] -= Y[0] ^ ((~Y[7])<<19); \
	Y[2] ^= Y[1]; \
	Y[3] += Y[2]; \
	Y[4] -= Y[3] ^ ((~Y[2])>>23); \
	Y[5] ^= Y[4]; \
	Y[6] += Y[5]; \
	Y[7] -= Y[6] ^ W64LIT(0x0123456789ABCDEF)

void Tiger::Transform (word64 *digest, const word64 *X)
{
	word64 a = digest[0];
	word64 b = digest[1];
	word64 c = digest[2];
	word64 Y[8];

	pass(a,b,c,5,X);
	key_schedule(Y,X);
	pass(c,a,b,7,Y);
	key_schedule(Y,Y);
	pass(b,c,a,9,Y);

	digest[0] = a ^ digest[0];
	digest[1] = b - digest[1];
	digest[2] = c + digest[2];

	Y[0] = Y[1] = Y[2] = Y[3] = Y[4] = Y[5] = Y[6] = Y[7] = 0;
}

NAMESPACE_END

#endif	// WORD64_AVAILABLE
