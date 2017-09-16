#ifndef CRYPTOPP_RIJNDAEL_H
#define CRYPTOPP_RIJNDAEL_H

#include "cryptlib.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

class Rijndael : public BlockTransformation
{
public:
	enum {KEYLENGTH=16, BLOCKSIZE=16};
	unsigned int BlockSize() const {return BLOCKSIZE;}
	static unsigned int KeyLength(unsigned int keylength)
		{return keylength <= 16 ? 16 : (keylength <= 24 ? 24 : 32);}

protected:
	Rijndael(const byte *userKey, unsigned int keylength);

	static const byte sbx_tab[256];
	static const byte isb_tab[256];
	static const word32 rco_tab[10];
	static const word32 ft_tab[4][256];
	static const word32 it_tab[4][256];

	word32 k_len;
	SecBlock<word32> key;
};

class RijndaelEncryption : public Rijndael
{
public:
	RijndaelEncryption(const byte *userKey, unsigned int keylength=KEYLENGTH)
		: Rijndael(userKey, keylength) {}

	void ProcessBlock(const byte *inBlock, byte * outBlock) const;
	void ProcessBlock(byte * inoutBlock) const
		{RijndaelEncryption::ProcessBlock(inoutBlock, inoutBlock);}
};

class RijndaelDecryption : public Rijndael
{
public:
	RijndaelDecryption(const byte *userKey, unsigned int keylength=KEYLENGTH);

	void ProcessBlock(const byte *inBlock, byte * outBlock) const;
	void ProcessBlock(byte * inoutBlock) const
		{RijndaelDecryption::ProcessBlock(inoutBlock, inoutBlock);}
};

NAMESPACE_END

#endif
