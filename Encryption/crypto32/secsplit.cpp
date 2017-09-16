// secsplit.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "secsplit.h"
#include "queue.h"

NAMESPACE_BEGIN(CryptoPP)

void SplitFork::Put(byte inByte)
{
	SecByteBlock buf(NumberOfPorts());

	rng.GetBlock(buf, NumberOfPorts()-1);
	buf[NumberOfPorts()-1] = inByte;

	for (int i=0; i<NumberOfPorts(); i++)
	{
		AccessPort(i).Put(buf[i]);
		buf[NumberOfPorts()-1] ^= buf[i];
	}
}

void SplitFork::Put(const byte *inString, unsigned int length)
{
	SecByteBlock randomBlock(length);
	SecByteBlock lastBlock(length);

	memcpy(lastBlock, inString, length);

	for (int i=0; i<NumberOfPorts()-1; i++)
	{
		rng.GetBlock(randomBlock, length);
		AccessPort(i).Put(randomBlock, length);
		xorbuf(lastBlock, randomBlock, length);
	}

	AccessPort(NumberOfPorts()-1).Put(lastBlock, length);
}

void SplitJoin::NotifyInput(unsigned int /* interfaceId */, unsigned int /* length */)
{
	unsigned long n=AccessPort(0).MaxRetrieveable();

	for (int i=1; n && i<NumberOfPorts(); i++)
		n = STDMIN(n, AccessPort(i).MaxRetrieveable());

	if (n)
	{
		const unsigned int l = (unsigned int) n;	// convert long to int
		SecByteBlock original(l);
		SecByteBlock buf(l);

		AccessPort(NumberOfPorts()-1).Get(original, l);
		for (int i=0; i<NumberOfPorts()-1; i++)
		{
			AccessPort(i).Get(buf, l);
			xorbuf(original, buf, l);
		}
		AttachedTransformation()->Put(original, l);
	}
}

NAMESPACE_END
