#ifndef CRYPTOPP_RC6_H
#define CRYPTOPP_RC6_H

#include "cryptlib.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

class RC6Base : public BlockTransformation
{
public:
	typedef word32 RC6_WORD;

	// values of KEYLENGTH and ROUNDS are defaults only
	enum {KEYLENGTH=16, BLOCKSIZE = sizeof(RC6_WORD)*4, ROUNDS=20};
	unsigned int BlockSize() const {return BLOCKSIZE;}
	static unsigned int KeyLength(unsigned int keylength)
		{return STDMIN(keylength, 255U);}

protected:
	RC6Base(const byte *key, unsigned int keyLen, unsigned int rounds);

	const unsigned int r;       // number of rounds
	SecBlock<RC6_WORD> sTable;  // expanded key table
};

class RC6Encryption : public RC6Base
{
public:
	RC6Encryption(const byte *key, unsigned int keyLen=KEYLENGTH, unsigned int rounds=ROUNDS)
		: RC6Base(key, keyLen, rounds) {}

	void ProcessBlock(byte * inoutBlock) const
		{RC6Encryption::ProcessBlock(inoutBlock, inoutBlock);}
	void ProcessBlock(const byte *inBlock, byte * outBlock) const;
};

class RC6Decryption : public RC6Base
{
public:
	RC6Decryption(const byte *key, unsigned int keyLen=KEYLENGTH, unsigned int rounds=ROUNDS)
		: RC6Base(key, keyLen, rounds) {}

	void ProcessBlock(byte * inoutBlock) const
		{RC6Decryption::ProcessBlock(inoutBlock, inoutBlock);}
	void ProcessBlock(const byte *inBlock, byte * outBlock) const;
};

NAMESPACE_END

#endif
