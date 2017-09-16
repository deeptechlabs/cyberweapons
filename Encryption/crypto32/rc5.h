#ifndef CRYPTOPP_RC5_H
#define CRYPTOPP_RC5_H

#include "cryptlib.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

class RC5Base : public BlockTransformation
{
public:
	typedef word32 RC5_WORD;

	// values of KEYLENGTH and ROUNDS are defaults only
	enum {KEYLENGTH=16, BLOCKSIZE = sizeof(RC5_WORD)*2, ROUNDS=12};  // == 8
	unsigned int BlockSize() const {return BLOCKSIZE;}
	static unsigned int KeyLength(unsigned int keylength)
		{return STDMIN(keylength, 255U);}

protected:
	RC5Base(const byte *key, unsigned int keyLen, unsigned int rounds);

	const unsigned int r;       // number of rounds
	SecBlock<RC5_WORD> sTable;  // expanded key table
};

class RC5Encryption : public RC5Base
{
public:
	RC5Encryption(const byte *key, unsigned int keyLen=KEYLENGTH, unsigned int rounds=ROUNDS)
		: RC5Base(key, keyLen, rounds) {}

	void ProcessBlock(byte * inoutBlock) const
		{RC5Encryption::ProcessBlock(inoutBlock, inoutBlock);}
	void ProcessBlock(const byte *inBlock, byte * outBlock) const;
};

class RC5Decryption : public RC5Base
{
public:
	RC5Decryption(const byte *key, unsigned int keyLen=KEYLENGTH, unsigned int rounds=ROUNDS)
		: RC5Base(key, keyLen, rounds) {}

	void ProcessBlock(byte * inoutBlock) const
		{RC5Decryption::ProcessBlock(inoutBlock, inoutBlock);}
	void ProcessBlock(const byte *inBlock, byte * outBlock) const;
};

NAMESPACE_END

#endif
