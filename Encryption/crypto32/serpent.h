#ifndef CRYPTOPP_SERPENT_H
#define CRYPTOPP_SERPENT_H

#include "cryptlib.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

class Serpent : public BlockTransformation
{
public:
	enum {KEYLENGTH=16, BLOCKSIZE=16, MAX_KEYLENGTH=32};
	unsigned int BlockSize() const {return BLOCKSIZE;}
	static unsigned int KeyLength(unsigned int keylength)
		{return keylength < 1 ? 1 : (keylength <= MAX_KEYLENGTH ? keylength : MAX_KEYLENGTH);}

protected:
	Serpent(const byte *userKey, unsigned int keylength);

	SecBlock<word32> l_key;
};

class SerpentEncryption : public Serpent
{
public:
	SerpentEncryption(const byte *userKey, unsigned int keylength=KEYLENGTH)
		: Serpent(userKey, keylength) {}

	void ProcessBlock(const byte *inBlock, byte * outBlock) const;
	void ProcessBlock(byte * inoutBlock) const
		{SerpentEncryption::ProcessBlock(inoutBlock, inoutBlock);}
};

class SerpentDecryption : public Serpent
{
public:
	SerpentDecryption(const byte *userKey, unsigned int keylength=KEYLENGTH)
		: Serpent(userKey, keylength) {}

	void ProcessBlock(const byte *inBlock, byte * outBlock) const;
	void ProcessBlock(byte * inoutBlock) const
		{SerpentDecryption::ProcessBlock(inoutBlock, inoutBlock);}
};

NAMESPACE_END

#endif
