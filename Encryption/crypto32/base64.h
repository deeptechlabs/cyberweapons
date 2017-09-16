#ifndef CRYPTOPP_BASE64_H
#define CRYPTOPP_BASE64_H

#include "cryptlib.h"
#include "filters.h"

NAMESPACE_BEGIN(CryptoPP)

class Base64Encoder : public Filter
{
public:
	Base64Encoder(BufferedTransformation *outQueue = NULL, bool insertLineBreak = true);

	void Put(byte inByte)
	{
		inBuf[inBufSize++]=inByte;
		if (inBufSize==3)
			EncodeQuantum();
	}

	void Put(const byte *inString, unsigned int length);
	void InputFinished();

private:
	void LineBreak();
	void EncodeQuantum();

	const bool insertLineBreak;
	int inBufSize;
	int lineLength;
	byte inBuf[3];
};

class Base64Decoder : public Filter
{
public:
	Base64Decoder(BufferedTransformation *outQueue = NULL);

	void Put(byte inByte)
	{
		int i=ConvToNumber(inByte);
		if (i >= 0)
			inBuf[inBufSize++]=(byte) i;
		if (inBufSize==4)
			DecodeQuantum();
	}

	void Put(const byte *inString, unsigned int length);
	void InputFinished();

private:
	static int ConvToNumber(byte inByte);
	void DecodeQuantum();

	int inBufSize;
	byte inBuf[4];
};

NAMESPACE_END

#endif
