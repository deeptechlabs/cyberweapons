#ifndef CRYPTOPP_TWOFISH_H
#define CRYPTOPP_TWOFISH_H

#include "cryptlib.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

class Twofish : public BlockTransformation
{
public:
	enum {KEYLENGTH=16, BLOCKSIZE=16};
	unsigned int BlockSize() const {return BLOCKSIZE;}
	static unsigned int KeyLength(unsigned int keylength)
		{return keylength <= 16 ? 16 : (keylength <= 24 ? 24 : 32);}

protected:
	Twofish(const byte *userKey, unsigned int keylength);
	word32 h_fun(const word32 x, const word32 key[]);
	void gen_mk_tab(word32 key[]);

	static const byte q_tab[2][256];
	static const word32 m_tab[4][256];

	unsigned int k_len;
	SecBlock<word32> l_key;
	SecBlock<word32[256]> mk_tab;
};

class TwofishEncryption : public Twofish
{
public:
	TwofishEncryption(const byte *userKey, unsigned int keylength=KEYLENGTH)
		: Twofish(userKey, keylength) {}

	void ProcessBlock(const byte *inBlock, byte * outBlock) const;
	void ProcessBlock(byte * inoutBlock) const
		{TwofishEncryption::ProcessBlock(inoutBlock, inoutBlock);}
};

class TwofishDecryption : public Twofish
{
public:
	TwofishDecryption(const byte *userKey, unsigned int keylength=KEYLENGTH)
		: Twofish(userKey, keylength) {}

	void ProcessBlock(const byte *inBlock, byte * outBlock) const;
	void ProcessBlock(byte * inoutBlock) const
		{TwofishDecryption::ProcessBlock(inoutBlock, inoutBlock);}
};

NAMESPACE_END

#endif
