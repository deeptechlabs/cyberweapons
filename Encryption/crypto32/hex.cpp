// hex.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "hex.h"

NAMESPACE_BEGIN(CryptoPP)

static const byte s_vecUpper[] = "0123456789ABCDEF";
static const byte s_vecLower[] = "0123456789abcdef";

HexEncoder::HexEncoder(BufferedTransformation *outQueue, bool uppercase)
	: Filter(outQueue), m_vec(uppercase ? s_vecUpper : s_vecLower)
{
}

void HexEncoder::Put(const byte *inString, unsigned int length)
{
	while (length--)
		HexEncoder::Put(*inString++);
}

void HexDecoder::Put(const byte *inString, unsigned int length)
{
	while (length--)
		HexDecoder::Put(*inString++);
}

NAMESPACE_END
