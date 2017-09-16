#ifndef CRYPTOPP_BLOWFISH_H
#define CRYPTOPP_BLOWFISH_H

#include "cryptlib.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

class Blowfish : public BlockTransformation
{
public:
	Blowfish(const byte *key_string, unsigned int keylength, CipherDir direction);

	void ProcessBlock(byte * inoutBlock) const
		{Blowfish::ProcessBlock(inoutBlock, inoutBlock);}
	void ProcessBlock(const byte *inBlock, byte *outBlock) const;

	// value of KEYLENGTH is default only
	enum {KEYLENGTH=16, BLOCKSIZE=8, ROUNDS=16, MAX_KEYLENGTH=(ROUNDS+2)*4};
	unsigned int BlockSize() const {return BLOCKSIZE;}
	static unsigned int KeyLength(unsigned int keylength)
		{return keylength < 1 ? 1 : (keylength <= MAX_KEYLENGTH ? keylength : MAX_KEYLENGTH);}

private:
	void crypt_block(const word32 in[2], word32 out[2]) const;

	static const word32 p_init[ROUNDS+2];
	static const word32 s_init[4*256];
	SecBlock<word32> pbox, sbox;
};

class BlowfishEncryption : public Blowfish
{
public:
	BlowfishEncryption(const byte *key_string, unsigned int keylength=KEYLENGTH)
		: Blowfish(key_string, keylength, ENCRYPTION) {}
};

class BlowfishDecryption : public Blowfish
{
public:
	BlowfishDecryption(const byte *key_string, unsigned int keylength=KEYLENGTH)
		: Blowfish(key_string, keylength, DECRYPTION) {}
};

NAMESPACE_END

#endif
