// randpool.cpp - written and placed in the public domain by Wei Dai
// The algorithm in this module comes from PGP's randpool.c

#include "pch.h"
#include "randpool.h"
#include "mdc.h"
#include "md5.h"
#include "modes.h"

NAMESPACE_BEGIN(CryptoPP)

typedef MDC<MD5> RandomPoolCipher;

RandomPool::RandomPool(unsigned int poolSize)
	: pool(poolSize), key(RandomPoolCipher::KEYLENGTH)
{
	assert(poolSize > key.size);

	addPos=0;
	getPos=poolSize;
	memset(pool, 0, poolSize);
	memset(key, 0, key.size);
}

void RandomPool::Stir()
{
//	add these lines to be compatible with PGP's randpool.c
//	byteReverse((word32 *)pool.ptr, (word32 *)pool.ptr, pool.size);
	for (int i=0; i<2; i++)
	{
		RandomPoolCipher cipher(key);
		CFBEncryption cfb(cipher, pool+pool.size-cipher.BlockSize());
		cfb.ProcessString(pool, pool.size);
		memcpy(key, pool, key.size);
	}
//	byteReverse((word32 *)pool.ptr, (word32 *)pool.ptr, pool.size);

	addPos = 0;
	getPos = key.size;
}

void RandomPool::Put(byte inByte)
{
	if (addPos == pool.size)
		Stir();

	pool[addPos++] ^= inByte;
	getPos = pool.size; // Force stir on get
}

void RandomPool::Put(const byte *inString, unsigned int length)
{
	unsigned t;

	while (length > (t = pool.size - addPos))
	{
		xorbuf(pool+addPos, inString, t);
		inString += t;
		length -= t;
		Stir();
	}

	if (length)
	{
		xorbuf(pool+addPos, inString, length);
		addPos += length;
		getPos = pool.size; // Force stir on get
	}
}

unsigned int RandomPool::Get(byte &outByte)
{
	if (getPos == pool.size)
		Stir();

	outByte = pool[getPos++];
	return 1;
}

unsigned int RandomPool::Get(byte *outString, unsigned int getMax)
{
	unsigned t;
	unsigned int length = getMax;

	while (length > (t = pool.size - getPos))
	{
		memcpy(outString, pool+getPos, t);
		outString += t;
		length -= t;
		Stir();
	}

	if (length)
	{
		memcpy(outString, pool+getPos, length);
		getPos += length;
	}
	return getMax;
}

NAMESPACE_END
