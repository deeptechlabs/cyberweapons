#ifndef CRYPTOPP_MODES_H
#define CRYPTOPP_MODES_H

#include "cryptlib.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

class CipherMode
{
protected:
	CipherMode(const BlockTransformation &cipher, const byte *IV);

	const BlockTransformation &cipher;
	const int S;
	SecByteBlock reg, buffer;    // register is a reserved word
};

class FeedBackMode : protected CipherMode
{
protected:
	// feedBackSize = 0 means use maximum feedback size (i.e., the cipher block size)
	FeedBackMode(const BlockTransformation &cipher, const byte *IV, int feedBackSize);
	void DoFeedBack();

	const int FBS;
	int counter;
};

class CFBEncryption : public StreamCipher, protected FeedBackMode
{
public:
	// cipher should be an *encryption* object
	CFBEncryption(const BlockTransformation &cipher, const byte *IV, int feedBackSize = 0)
    	: FeedBackMode(cipher, IV, feedBackSize) {}

	byte ProcessByte(byte input)
	{
		if (counter==FBS)
			DoFeedBack();
		buffer[counter] ^= input;
		return buffer[counter++];
	}

	void ProcessString(byte *outString, const byte *inString, unsigned int length);
	void ProcessString(byte *inoutString, unsigned int length);
};

class CFBDecryption : public StreamCipher, protected FeedBackMode
{
public:
	// cipher should be an *encryption* object
	CFBDecryption(const BlockTransformation &cipher, const byte *IV, int feedBackSize = 0)
    	: FeedBackMode(cipher, IV, feedBackSize) {}

	byte ProcessByte(byte input)
	{
		if (counter==FBS)
			DoFeedBack();
		byte b = buffer[counter] ^ input;
		buffer[counter++] = input;
		return (b);
	}

	void ProcessString(byte *outString, const byte *inString, unsigned int length);
	void ProcessString(byte *inoutString, unsigned int length);
};

class OFB : public RandomNumberGenerator, public StreamCipher, protected FeedBackMode
{
public:
	// cipher should be an *encryption* object
	OFB(const BlockTransformation &cipher, const byte *IV, int feedBackSize = 0)
    	: FeedBackMode(cipher, IV, feedBackSize) {}

	byte GetByte()
	{
		if (counter==FBS)
			DoFeedBack();
		return buffer[counter++];
	}

	byte ProcessByte(byte input)
		{return (input ^ OFB::GetByte());}

	void ProcessString(byte *outString, const byte *inString, unsigned int length);
	void ProcessString(byte *inoutString, unsigned int length);
};

class CounterMode : public RandomNumberGenerator, public RandomAccessStreamCipher, protected CipherMode
{
public:
	// cipher should be an *encryption* object
	CounterMode(const BlockTransformation &cipher, const byte *IV);

	byte GetByte()
	{
		if (size==S)
			IncrementCounter();
		return buffer[size++];
	}

	byte ProcessByte(byte input)
		{return (input ^ CounterMode::GetByte());}

	void ProcessString(byte *outString, const byte *inString, unsigned int length);
	void ProcessString(byte *inoutString, unsigned int length);

	void Seek(unsigned long position);

private:
	void IncrementCounter();

	SecByteBlock IV;
	int size;
};

class PGP_CFBEncryption : public CFBEncryption
{
public:
	// cipher should be an *encryption* object
	PGP_CFBEncryption(const BlockTransformation &cipher, const byte *IV)
    	: CFBEncryption(cipher, IV, 0) {}

	void Sync();
};

class PGP_CFBDecryption : public CFBDecryption
{
public:
	// cipher should be an *encryption* object
	PGP_CFBDecryption(const BlockTransformation &cipher, const byte *IV)
    	: CFBDecryption(cipher, IV, 0) {}

	void Sync();
};

NAMESPACE_END

#endif
