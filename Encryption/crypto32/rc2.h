#ifndef CRYPTOPP_RC2_H
#define CRYPTOPP_RC2_H

#include "cryptlib.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

class RC2Base : public BlockTransformation
{
public:
	// values of KEYLENGTH is defaults only
	enum {KEYLENGTH=16, BLOCKSIZE=8, ROUNDS=18};
	unsigned int BlockSize() const {return BLOCKSIZE;}
	static unsigned int KeyLength(unsigned int keylength)
		{return keylength < 1 ? 1 : (keylength <= 128 ? keylength : 128);}

protected:
	// max keyLen is 128, max effectiveLen is 1024
	RC2Base(const byte *key, unsigned int keyLen, unsigned int effectiveLen);

	SecBlock<word16> K;  // expanded key table
};

class RC2Encryption : public RC2Base
{
public:
	RC2Encryption(const byte *key, unsigned int keyLen=KEYLENGTH, unsigned int effectiveLen=1024)
		: RC2Base(key, keyLen, effectiveLen) {}

	void ProcessBlock(byte * inoutBlock) const
		{RC2Encryption::ProcessBlock(inoutBlock, inoutBlock);}
	void ProcessBlock(const byte *inBlock, byte * outBlock) const;
};

class RC2Decryption : public RC2Base
{
public:
	RC2Decryption(const byte *key, unsigned int keyLen=KEYLENGTH, unsigned int effectiveLen=1024)
		: RC2Base(key, keyLen, effectiveLen) {}

	void ProcessBlock(byte * inoutBlock) const
		{RC2Decryption::ProcessBlock(inoutBlock, inoutBlock);}
	void ProcessBlock(const byte *inBlock, byte * outBlock) const;
};

NAMESPACE_END

#endif
