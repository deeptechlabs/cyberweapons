// tea.cpp - modified by Wei Dai from code in the original paper

#include "pch.h"
#include "tea.h"

NAMESPACE_BEGIN(CryptoPP)

const word32 TEA::DELTA = 0x9e3779b9;

TEA::TEA(const byte *userKey)
	: k(4)
{
	GetUserKeyBigEndian(k.ptr, 4, userKey, KEYLENGTH);
}

void TEAEncryption::ProcessBlock(const byte *in, byte *out) const
{
	word32 y, z;
	GetBlockBigEndian(in, y, z);

	word32 sum = 0;
	for (int i=0; i<ROUNDS; i++)
	{   
		sum += DELTA;
		y += (z << 4) + k[0] ^ z + sum ^ (z >> 5) + k[1];
		z += (y << 4) + k[2] ^ y + sum ^ (y >> 5) + k[3];
	}

	PutBlockBigEndian(out, y, z);
}

void TEADecryption::ProcessBlock(const byte *in, byte *out) const
{
	word32 y, z;
	GetBlockBigEndian(in, y, z);

	word32 sum = DELTA << LOG_ROUNDS;
	for (int i=0; i<ROUNDS; i++)
	{
		z -= (y << 4) + k[2] ^ y + sum ^ (y >> 5) + k[3]; 
		y -= (z << 4) + k[0] ^ z + sum ^ (z >> 5) + k[1];
		sum -= DELTA;
	}

	PutBlockBigEndian(out, y, z);
}

NAMESPACE_END
