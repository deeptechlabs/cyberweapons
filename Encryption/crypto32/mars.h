#ifndef CRYPTOPP_MARS_H
#define CRYPTOPP_MARS_H

#include "cryptlib.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

class MARS : public BlockTransformation
{
public:
	enum {KEYLENGTH=16, BLOCKSIZE=16};
	unsigned int BlockSize() const {return BLOCKSIZE;}
	static unsigned int KeyLength(unsigned int keylength)
		{return keylength < 1 ? 1 : (keylength <= 39 ? keylength : 39);}

protected:
	MARS(const byte *userKey, unsigned int keylength);

	static const word32 Sbox[512];

	SecBlock<word32> EK;
};

class MARSEncryption : public MARS
{
public:
	MARSEncryption(const byte *userKey, unsigned int keylength=KEYLENGTH)
		: MARS(userKey, keylength) {}

	void ProcessBlock(const byte *inBlock, byte * outBlock) const;
	void ProcessBlock(byte * inoutBlock) const
		{MARSEncryption::ProcessBlock(inoutBlock, inoutBlock);}
};

class MARSDecryption : public MARS
{
public:
	MARSDecryption(const byte *userKey, unsigned int keylength=KEYLENGTH)
		: MARS(userKey, keylength) {}

	void ProcessBlock(const byte *inBlock, byte * outBlock) const;
	void ProcessBlock(byte * inoutBlock) const
		{MARSDecryption::ProcessBlock(inoutBlock, inoutBlock);}
};

NAMESPACE_END

#endif
