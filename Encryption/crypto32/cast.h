#ifndef CRYPTOPP_CAST_H
#define CRYPTOPP_CAST_H

#include "cryptlib.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

class CAST128 : public BlockTransformation
{
public:
	enum {KEYLENGTH=16, BLOCKSIZE=8};
	unsigned int BlockSize() const {return BLOCKSIZE;}
	static unsigned int KeyLength(unsigned int keylength)
		{return keylength < 5 ? 5 : (keylength <= 16 ? keylength : 16);}

protected:
	// keylength should be between 5 and 16
	CAST128(const byte *userKey, unsigned int keylength);

	static const word32 S[8][256];

	bool reduced;
	SecBlock<word32> K;
};

class CAST128Encryption : public CAST128
{
public:
	CAST128Encryption(const byte *userKey, unsigned int keylength=KEYLENGTH)
		: CAST128(userKey, keylength) {}

	void ProcessBlock(const byte *inBlock, byte * outBlock) const;
	void ProcessBlock(byte * inoutBlock) const
		{CAST128Encryption::ProcessBlock(inoutBlock, inoutBlock);}
};

class CAST128Decryption : public CAST128
{
public:
	CAST128Decryption(const byte *userKey, unsigned int keylength=KEYLENGTH)
		: CAST128(userKey, keylength) {}

	void ProcessBlock(const byte *inBlock, byte * outBlock) const;
	void ProcessBlock(byte * inoutBlock) const
		{CAST128Decryption::ProcessBlock(inoutBlock, inoutBlock);}
};

NAMESPACE_END

#endif
