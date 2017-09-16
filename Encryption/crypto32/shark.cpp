// shark.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "shark.h"

#ifdef WORD64_AVAILABLE

#include "modes.h"
#include "gf256.h"

NAMESPACE_BEGIN(CryptoPP)

static word64 SHARKTransform(word64 a)
{
	static const byte iG[8][8] = {
		0xe7, 0x30, 0x90, 0x85, 0xd0, 0x4b, 0x91, 0x41, 
		0x53, 0x95, 0x9b, 0xa5, 0x96, 0xbc, 0xa1, 0x68, 
		0x02, 0x45, 0xf7, 0x65, 0x5c, 0x1f, 0xb6, 0x52, 
		0xa2, 0xca, 0x22, 0x94, 0x44, 0x63, 0x2a, 0xa2, 
		0xfc, 0x67, 0x8e, 0x10, 0x29, 0x75, 0x85, 0x71, 
		0x24, 0x45, 0xa2, 0xcf, 0x2f, 0x22, 0xc1, 0x0e, 
		0xa1, 0xf1, 0x71, 0x40, 0x91, 0x27, 0x18, 0xa5, 
		0x56, 0xf4, 0xaf, 0x32, 0xd2, 0xa4, 0xdc, 0x71, 
	};

	word64 result=0;
	GF256 gf256(0xf5);
	for (unsigned int i=0; i<8; i++)
		for(unsigned int j=0; j<8; j++) 
			result ^= word64(gf256.Multiply(iG[i][j], a>>(56-8*j))) << (56-8*i);
	return result;
}

void SHARKBase::InitEncryptionRoundKeys(const byte *key, unsigned int keyLen, unsigned int rounds, word64 *roundkeys)
{
	assert(keyLen == KeyLength(keyLen));

	// concatenate key enought times to fill a
	for (unsigned int i=0; i<(rounds+1)*8; i++)
		((byte *)roundkeys)[i] = key[i%keyLen];

	SHARKEncryption e;
	byte IV[8] = {0,0,0,0,0,0,0,0};
	CFBEncryption cfb(e, IV);

	cfb.ProcessString((byte *)roundkeys, (rounds+1)*8);

#ifdef IS_LITTLE_ENDIAN
	byteReverse(roundkeys, roundkeys, (rounds+1)*8);
#endif

	roundkeys[rounds] = SHARKTransform(roundkeys[rounds]);
}

// construct an SHARKEncryption object with fixed round keys, to be used to initialize actual round keys
SHARKEncryption::SHARKEncryption()
	: SHARKBase(ROUNDS)
{
	for (unsigned int i=0; i<ROUNDS; i++)
		roundkeys[i] = cbox[0][i];

	roundkeys[ROUNDS] = SHARKTransform(cbox[0][ROUNDS]);

#ifdef IS_LITTLE_ENDIAN
	roundkeys[0] = byteReverse(roundkeys[0]);
	roundkeys[ROUNDS] = byteReverse(roundkeys[ROUNDS]);
#endif
}

SHARKEncryption::SHARKEncryption(const byte *key, unsigned int keyLen, unsigned int rounds)
	: SHARKBase(rounds)
{
	InitEncryptionRoundKeys(key, keyLen, rounds, roundkeys);

#ifdef IS_LITTLE_ENDIAN
	roundkeys[0] = byteReverse(roundkeys[0]);
	roundkeys[rounds] = byteReverse(roundkeys[rounds]);
#endif
}

void SHARKEncryption::ProcessBlock(const byte *in, byte *out) const
{
	word64 tmp = *(word64 *)in ^ roundkeys[0];

#ifdef IS_LITTLE_ENDIAN
	tmp = cbox[0][GETBYTE(tmp, 0)] ^ cbox[1][GETBYTE(tmp, 1)] 
		^ cbox[2][GETBYTE(tmp, 2)] ^ cbox[3][GETBYTE(tmp, 3)] 
		^ cbox[4][GETBYTE(tmp, 4)] ^ cbox[5][GETBYTE(tmp, 5)] 
		^ cbox[6][GETBYTE(tmp, 6)] ^ cbox[7][GETBYTE(tmp, 7)]
		^ roundkeys[1];
#else
	tmp = cbox[0][GETBYTE(tmp, 7)] ^ cbox[1][GETBYTE(tmp, 6)] 
		^ cbox[2][GETBYTE(tmp, 5)] ^ cbox[3][GETBYTE(tmp, 4)] 
		^ cbox[4][GETBYTE(tmp, 3)] ^ cbox[5][GETBYTE(tmp, 2)] 
		^ cbox[6][GETBYTE(tmp, 1)] ^ cbox[7][GETBYTE(tmp, 0)]
		^ roundkeys[1];
#endif

	for(unsigned int i=2; i<rounds; i++) 
	{
		tmp = cbox[0][GETBYTE(tmp, 7)] ^ cbox[1][GETBYTE(tmp, 6)] 
			^ cbox[2][GETBYTE(tmp, 5)] ^ cbox[3][GETBYTE(tmp, 4)] 
			^ cbox[4][GETBYTE(tmp, 3)] ^ cbox[5][GETBYTE(tmp, 2)] 
			^ cbox[6][GETBYTE(tmp, 1)] ^ cbox[7][GETBYTE(tmp, 0)]
			^ roundkeys[i];
	}

	out[0] = sbox[GETBYTE(tmp, 7)];
	out[1] = sbox[GETBYTE(tmp, 6)];
	out[2] = sbox[GETBYTE(tmp, 5)];
	out[3] = sbox[GETBYTE(tmp, 4)];
	out[4] = sbox[GETBYTE(tmp, 3)];
	out[5] = sbox[GETBYTE(tmp, 2)];
	out[6] = sbox[GETBYTE(tmp, 1)];
	out[7] = sbox[GETBYTE(tmp, 0)];

	*(word64 *)out ^= roundkeys[rounds];
}

SHARKDecryption::SHARKDecryption(const byte *key, unsigned int keyLen, unsigned int rounds)
	: SHARKBase(rounds)
{
	InitEncryptionRoundKeys(key, keyLen, rounds, roundkeys);

	unsigned int i;

	// transform encryption round keys into decryption round keys
	for (i=0; i<rounds/2; i++)
		std::swap(roundkeys[i], roundkeys[rounds-i]);

	for (i=1; i<rounds; i++)
		roundkeys[i] = SHARKTransform(roundkeys[i]);

#ifdef IS_LITTLE_ENDIAN
	roundkeys[0] = byteReverse(roundkeys[0]);
	roundkeys[rounds] = byteReverse(roundkeys[rounds]);
#endif
}

void SHARKDecryption::ProcessBlock(const byte *in, byte *out) const
{
	word64 tmp = *(word64 *)in ^ roundkeys[0];

#ifdef IS_LITTLE_ENDIAN
	tmp = cbox[0][GETBYTE(tmp, 0)] ^ cbox[1][GETBYTE(tmp, 1)] 
		^ cbox[2][GETBYTE(tmp, 2)] ^ cbox[3][GETBYTE(tmp, 3)] 
		^ cbox[4][GETBYTE(tmp, 4)] ^ cbox[5][GETBYTE(tmp, 5)] 
		^ cbox[6][GETBYTE(tmp, 6)] ^ cbox[7][GETBYTE(tmp, 7)]
		^ roundkeys[1];
#else
	tmp = cbox[0][GETBYTE(tmp, 7)] ^ cbox[1][GETBYTE(tmp, 6)] 
		^ cbox[2][GETBYTE(tmp, 5)] ^ cbox[3][GETBYTE(tmp, 4)] 
		^ cbox[4][GETBYTE(tmp, 3)] ^ cbox[5][GETBYTE(tmp, 2)] 
		^ cbox[6][GETBYTE(tmp, 1)] ^ cbox[7][GETBYTE(tmp, 0)]
		^ roundkeys[1];
#endif

	for(unsigned int i=2; i<rounds; i++) 
	{
		tmp = cbox[0][GETBYTE(tmp, 7)] ^ cbox[1][GETBYTE(tmp, 6)] 
			^ cbox[2][GETBYTE(tmp, 5)] ^ cbox[3][GETBYTE(tmp, 4)] 
			^ cbox[4][GETBYTE(tmp, 3)] ^ cbox[5][GETBYTE(tmp, 2)] 
			^ cbox[6][GETBYTE(tmp, 1)] ^ cbox[7][GETBYTE(tmp, 0)]
			^ roundkeys[i];
	}

	out[0] = sbox[GETBYTE(tmp, 7)];
	out[1] = sbox[GETBYTE(tmp, 6)];
	out[2] = sbox[GETBYTE(tmp, 5)];
	out[3] = sbox[GETBYTE(tmp, 4)];
	out[4] = sbox[GETBYTE(tmp, 3)];
	out[5] = sbox[GETBYTE(tmp, 2)];
	out[6] = sbox[GETBYTE(tmp, 1)];
	out[7] = sbox[GETBYTE(tmp, 0)];

	*(word64 *)out ^= roundkeys[rounds];
}

NAMESPACE_END

#endif // WORD64_AVAILABLE
