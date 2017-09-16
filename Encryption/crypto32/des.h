#ifndef CRYPTOPP_DES_H
#define CRYPTOPP_DES_H

#include "cryptlib.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

class DES : public BlockTransformation
{
public:
	DES(const byte *userKey, CipherDir);

	void ProcessBlock(const byte *inBlock, byte * outBlock) const;
	void ProcessBlock(byte * inoutBlock) const
		{DES::ProcessBlock(inoutBlock, inoutBlock);}

	enum {KEYLENGTH=8, BLOCKSIZE=8};
	unsigned int BlockSize() const {return BLOCKSIZE;}
	static unsigned int KeyLength(unsigned int keylength) {return KEYLENGTH;}

	// exposed for faster Triple-DES
	void RawProcessBlock(word32 &l, word32 &r) const;

protected:
	static const word32 Spbox[8][64];

	SecBlock<word32> k;
};

class DESEncryption : public DES
{
public:
	DESEncryption(const byte * userKey, unsigned int = 0)
		: DES (userKey, ENCRYPTION) {}
};

class DESDecryption : public DES
{
public:
	DESDecryption(const byte * userKey, unsigned int = 0)
		: DES (userKey, DECRYPTION) {}
};

// two key triple-des

class DES_EDE2_Encryption : public BlockTransformation
{
public:
	DES_EDE2_Encryption(const byte * userKey, unsigned int = 0)
		: e(userKey, ENCRYPTION), d(userKey + DES::KEYLENGTH, DECRYPTION) {}

	void ProcessBlock(const byte *inBlock, byte * outBlock) const;
	void ProcessBlock(byte * inoutBlock) const
		{DES_EDE2_Encryption::ProcessBlock(inoutBlock, inoutBlock);}

	enum {KEYLENGTH=16, BLOCKSIZE=8};
	unsigned int BlockSize() const {return BLOCKSIZE;}
	static unsigned int KeyLength(unsigned int keylength) {return KEYLENGTH;}

private:
	DES e, d;
};

class DES_EDE2_Decryption : public BlockTransformation
{
public:
	DES_EDE2_Decryption(const byte * userKey, unsigned int = 0)
		: d(userKey, DECRYPTION), e(userKey + DES::KEYLENGTH, ENCRYPTION) {}

	void ProcessBlock(const byte *inBlock, byte * outBlock) const;
	void ProcessBlock(byte * inoutBlock) const
		{DES_EDE2_Decryption::ProcessBlock(inoutBlock, inoutBlock);}

	enum {KEYLENGTH=16, BLOCKSIZE=8};
	unsigned int BlockSize() const {return BLOCKSIZE;}
	static unsigned int KeyLength(unsigned int keylength) {return KEYLENGTH;}

private:
	DES d, e;
};

// three key triple-des

class DES_EDE3_Encryption : public BlockTransformation
{
public:
	DES_EDE3_Encryption(const byte * userKey, unsigned int = 0)
		: e1(userKey, ENCRYPTION), d2(userKey + DES::KEYLENGTH, DECRYPTION),
		  e3(userKey + 2*DES::KEYLENGTH, ENCRYPTION) {}

	void ProcessBlock(const byte *inBlock, byte * outBlock) const;
	void ProcessBlock(byte * inoutBlock) const
		{DES_EDE3_Encryption::ProcessBlock(inoutBlock, inoutBlock);}

	enum {KEYLENGTH=24, BLOCKSIZE=8};
	unsigned int BlockSize() const {return BLOCKSIZE;}
	static unsigned int KeyLength(unsigned int keylength) {return KEYLENGTH;}

private:
	DES e1, d2, e3;
};

class DES_EDE3_Decryption : public BlockTransformation
{
public:
	DES_EDE3_Decryption(const byte * userKey, unsigned int = 0)
		: d1(userKey, DECRYPTION), e2(userKey + DES::KEYLENGTH, ENCRYPTION),
		  d3(userKey + 2*DES::KEYLENGTH, DECRYPTION) {}

	void ProcessBlock(const byte *inBlock, byte * outBlock) const;
	void ProcessBlock(byte * inoutBlock) const
		{DES_EDE3_Decryption::ProcessBlock(inoutBlock, inoutBlock);}

	enum {KEYLENGTH=24, BLOCKSIZE=8};
	unsigned int BlockSize() const {return BLOCKSIZE;}
	static unsigned int KeyLength(unsigned int keylength) {return KEYLENGTH;}

private:
	DES d1, e2, d3;
};

// also known as DESX

class DES_XEX3_Encryption : public BlockTransformation
{
public:
	DES_XEX3_Encryption(const byte * userKey, unsigned int = 0)
		: x1(userKey, 8), e2(userKey + 8, ENCRYPTION), x3(userKey + 16, 8) {}

	void ProcessBlock(const byte *inBlock, byte * outBlock) const;
	void ProcessBlock(byte * inoutBlock) const
		{DES_XEX3_Encryption::ProcessBlock(inoutBlock, inoutBlock);}

	enum {KEYLENGTH=24, BLOCKSIZE=8};
	unsigned int BlockSize() const {return BLOCKSIZE;}
	static unsigned int KeyLength(unsigned int keylength) {return KEYLENGTH;}

private:
	SecByteBlock x1;
	DES e2;
	SecByteBlock x3;
};

class DES_XEX3_Decryption : public BlockTransformation
{
public:
	DES_XEX3_Decryption(const byte * userKey, unsigned int = 0)
		: x1(userKey, 8), d2(userKey + 8, DECRYPTION), x3(userKey + 16, 8) {}

	void ProcessBlock(const byte *inBlock, byte * outBlock) const;
	void ProcessBlock(byte * inoutBlock) const
		{DES_XEX3_Decryption::ProcessBlock(inoutBlock, inoutBlock);}

	enum {KEYLENGTH=24, BLOCKSIZE=8};
	unsigned int BlockSize() const {return BLOCKSIZE;}
	static unsigned int KeyLength(unsigned int keylength) {return KEYLENGTH;}

private:
	SecByteBlock x1;
	DES d2;
	SecByteBlock x3;
};

NAMESPACE_END

#endif
