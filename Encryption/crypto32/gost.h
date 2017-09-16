#ifndef CRYPTOPP_GOST_H
#define CRYPTOPP_GOST_H

#include "cryptlib.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

class GOST : public BlockTransformation
{
public:
	GOST(const byte *userKey, CipherDir);

	enum {KEYLENGTH=32, BLOCKSIZE=8};
	unsigned int BlockSize() const {return BLOCKSIZE;}
	static unsigned int KeyLength(unsigned int keylength) {return KEYLENGTH;}

protected:
	static void PrecalculateSTable();

	static const byte sBox[8][16];
	static bool sTableCalculated;
	static word32 sTable[4][256];

	SecBlock<word32> key;
};

class GOSTEncryption : public GOST
{
public:
	GOSTEncryption(const byte * userKey, unsigned int = 0)
		: GOST (userKey, ENCRYPTION) {}

	void ProcessBlock(const byte *inBlock, byte * outBlock) const;
	void ProcessBlock(byte * inoutBlock) const
		{GOSTEncryption::ProcessBlock(inoutBlock, inoutBlock);}
};

class GOSTDecryption : public GOST
{
public:
	GOSTDecryption(const byte * userKey, unsigned int = 0)
		: GOST (userKey, DECRYPTION) {}

	void ProcessBlock(const byte *inBlock, byte * outBlock) const;
	void ProcessBlock(byte * inoutBlock) const
		{GOSTDecryption::ProcessBlock(inoutBlock, inoutBlock);}
};

NAMESPACE_END

#endif
