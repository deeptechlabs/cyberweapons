// cbc.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "cbc.h"

NAMESPACE_BEGIN(CryptoPP)

CBCPaddedEncryptor::CBCPaddedEncryptor(const BlockTransformation &cipher, const byte *IV, BufferedTransformation *outQueue)
	: CipherMode(cipher, IV), FilterWithBufferedInput(0, S, 0, outQueue)
{
}

void CBCPaddedEncryptor::NextPut(const byte *inString, unsigned int)
{
	xorbuf(reg, inString, S);
	cipher.ProcessBlock(reg);
	AttachedTransformation()->Put(reg, S);
}

void CBCPaddedEncryptor::LastPut(const byte *inString, unsigned int length)
{
	// pad last block
	assert(length < S);
	xorbuf(reg, inString, length);
	byte pad = S-length;
	for (unsigned int i=0; i<pad; i++)
		reg[length+i] ^= pad;
	cipher.ProcessBlock(reg);
	AttachedTransformation()->Put(reg, S);
}

CBCPaddedDecryptor::CBCPaddedDecryptor(const BlockTransformation &cipher, const byte *IV, BufferedTransformation *outQueue)
	: CipherMode(cipher, IV), FilterWithBufferedInput(0, S, S, outQueue)
{
}

void CBCPaddedDecryptor::NextPut(const byte *inString, unsigned int)
{
	cipher.ProcessBlock(inString, buffer);
	xorbuf(buffer, reg, S);
	AttachedTransformation()->Put(buffer, S);
	memcpy(reg, inString, S);
}

void CBCPaddedDecryptor::LastPut(const byte *inString, unsigned int length)
{
	if (length >= S)
	{
		cipher.ProcessBlock(inString, buffer);
		xorbuf(buffer, reg, S);
		if (buffer[S-1] > S)
			buffer[S-1] = 0;	 // something's wrong with the padding
		AttachedTransformation()->Put(buffer, S-buffer[S-1]);
	}
}

// ********************************************************

CBC_CTS_Encryptor::CBC_CTS_Encryptor(const BlockTransformation &cipher, const byte *IV, BufferedTransformation *outQueue)
	: CipherMode(cipher, IV), FilterWithBufferedInput(S, S, 1, outQueue)
{
}

void CBC_CTS_Encryptor::FirstPut(const byte *inString)
{
	xorbuf(reg, inString, S);
	cipher.ProcessBlock(reg);
}

void CBC_CTS_Encryptor::NextPut(const byte *inString, unsigned int)
{
	AttachedTransformation()->Put(reg, S);
	xorbuf(reg, inString, S);
	cipher.ProcessBlock(reg);
}

void CBC_CTS_Encryptor::LastPut(const byte *inString, unsigned int length)
{
	assert(length <= S);
	if (!DidFirstPut())
	{
		xorbuf(reg, inString, length);
		cipher.ProcessBlock(reg);
		length = 0;
	}

	// output last full ciphertext block first
	buffer = reg;
	xorbuf(reg, inString, length);
	cipher.ProcessBlock(reg);
	AttachedTransformation()->Put(reg, S);
	// steal ciphertext from next to last block
	AttachedTransformation()->Put(buffer, STDMAX(length, 1U));
}

CBC_CTS_Decryptor::CBC_CTS_Decryptor(const BlockTransformation &cipher, const byte *IV, BufferedTransformation *outQueue)
	: CipherMode(cipher, IV), FilterWithBufferedInput(0, S, S+1, outQueue)
{
}

void CBC_CTS_Decryptor::NextPut(const byte *inString, unsigned int)
{
	cipher.ProcessBlock(inString, buffer);
	xorbuf(buffer, reg, S);
	memcpy(reg, inString, S);
	AttachedTransformation()->Put(buffer, S);
}

void CBC_CTS_Decryptor::LastPut(const byte *inString, unsigned int length)
{
	assert(length <= 2*S);
	if (length >= S+1)
	{
		length -= S;
		SecByteBlock temp(S);

		// decrypt last partial plaintext block
		cipher.ProcessBlock(inString, temp);
		xorbuf(temp, inString+S, length);

		// decrypt next to last plaintext block
		memcpy(buffer, inString+S, length);
		memcpy(buffer+length, temp+length, S-length);
		cipher.ProcessBlock(buffer);
		xorbuf(buffer, reg, S);

		AttachedTransformation()->Put(buffer, S);
		AttachedTransformation()->Put(temp, length);
	}
}

NAMESPACE_END
