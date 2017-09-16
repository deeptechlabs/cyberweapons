// base64.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "base64.h"

NAMESPACE_BEGIN(CryptoPP)

static const int MAX_LINE_LENGTH = 72;

static const byte vec[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const byte padding = '=';
   
Base64Encoder::Base64Encoder(BufferedTransformation *outQueue, bool insertLineBreak)
	: insertLineBreak(insertLineBreak), Filter(outQueue)
{
	inBufSize=0;
	lineLength=0;
}

void Base64Encoder::LineBreak()
{
	if (insertLineBreak)
		AttachedTransformation()->Put('\n');
	lineLength=0;
}

void Base64Encoder::EncodeQuantum()
{
	byte out;

	out=(inBuf[0] & 0xFC) >> 2;
	AttachedTransformation()->Put(vec[out]);

	out=((inBuf[0] & 0x03) << 4) | (inBuf[1] >> 4);
	AttachedTransformation()->Put(vec[out]);

	out=((inBuf[1] & 0x0F) << 2) | (inBuf[2] >> 6);
	AttachedTransformation()->Put(inBufSize > 1 ? vec[out] : padding);

	out=inBuf[2] & 0x3F;
	AttachedTransformation()->Put(inBufSize > 2 ? vec[out] : padding);

	inBufSize=0;
	lineLength+=4;

	if (lineLength>=MAX_LINE_LENGTH)
		LineBreak();
}

void Base64Encoder::Put(const byte *inString, unsigned int length)
{
	while (length--)
		Base64Encoder::Put(*inString++);
}

void Base64Encoder::InputFinished()
{
	if (inBufSize)
	{
		for (int i=inBufSize;i<3;i++)
			inBuf[i]=0;
		EncodeQuantum();
	}

	if (lineLength) // force a line break unless the current line is empty
		LineBreak();
}

Base64Decoder::Base64Decoder(BufferedTransformation *outQueue)
	: Filter(outQueue)
{
	inBufSize=0;
}

void Base64Decoder::DecodeQuantum()
{
	byte out;

	out = (inBuf[0] << 2) | (inBuf[1] >> 4);
	AttachedTransformation()->Put(out);

	out = (inBuf[1] << 4) | (inBuf[2] >> 2);
	if (inBufSize > 2) AttachedTransformation()->Put(out);

	out = (inBuf[2] << 6) | inBuf[3];
	if (inBufSize > 3) AttachedTransformation()->Put(out);

	inBufSize=0;
}

int Base64Decoder::ConvToNumber(byte inByte)
{
	if (inByte >= 'A' && inByte <= 'Z')
		return (inByte - 'A');

	if (inByte >= 'a' && inByte <= 'z')
		return (inByte - 'a' + 26);

	if (inByte >= '0' && inByte <= '9')
		return (inByte - '0' + 52);

	if (inByte == '+')
		return (62);

	if (inByte == '/')
		return (63);

	return (-1);
}

void Base64Decoder::Put(const byte *inString, unsigned int length)
{
	while (length--)
		Base64Decoder::Put(*inString++);
}

void Base64Decoder::InputFinished()
{
	if (inBufSize)
	{
		for (int i=inBufSize;i<4;i++)
			inBuf[i]=0;
		DecodeQuantum();
	}
}

NAMESPACE_END
