#ifndef CRYPTOPP_SQUARE_H
#define CRYPTOPP_SQUARE_H

#include "config.h"

#include "cryptlib.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

class SquareBase : public BlockTransformation
{
public:
	enum {KEYLENGTH=16, BLOCKSIZE=16, ROUNDS=8};
	unsigned int BlockSize() const {return BLOCKSIZE;}
	static unsigned int KeyLength(unsigned int keylength) {return KEYLENGTH;}

protected:
	SquareBase(const byte *userKey, CipherDir dir);

	SecBlock<word32[4]> roundkeys;
};

class SquareEncryption : public SquareBase
{
public:
	SquareEncryption(const byte *key, unsigned int = 0) : SquareBase(key, ENCRYPTION) {}

	void ProcessBlock(byte * inoutBlock) const
		{SquareEncryption::ProcessBlock(inoutBlock, inoutBlock);}
	void ProcessBlock(const byte *inBlock, byte * outBlock) const;

private:
	static const byte Se[256];
	static const word32 Te[4][256];
};

class SquareDecryption : public SquareBase
{
public:
	SquareDecryption(const byte *key, unsigned int = 0) : SquareBase(key, DECRYPTION) {}

	void ProcessBlock(byte * inoutBlock) const
		{SquareDecryption::ProcessBlock(inoutBlock, inoutBlock);}
	void ProcessBlock(const byte *inBlock, byte * outBlock) const;

private:
	static const byte Sd[256];
	static const word32 Td[4][256];
};

NAMESPACE_END

#endif
