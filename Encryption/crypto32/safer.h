#ifndef CRYPTOPP_SAFER_H
#define CRYPTOPP_SAFER_H

#include "cryptlib.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

class SAFER : public BlockTransformation
{
public:
	enum {BLOCKSIZE=8, MAX_ROUNDS=13};
	unsigned int BlockSize() const {return BLOCKSIZE;}

protected:
	SAFER(const byte *userkey_1, const byte *userkey_2, unsigned nof_rounds, bool strengthened);

	void Encrypt(const byte *inBlock, byte *outBlock) const;
	void Decrypt(const byte *inBlock, byte *outBlock) const;

	SecByteBlock keySchedule;
	static const byte exp_tab[256];
	static const byte log_tab[256];
};

class SAFER_K64_Encryption : public SAFER
{
public:
	enum {KEYLENGTH=8, ROUNDS=6};
	static unsigned int KeyLength(unsigned int keylength) {return KEYLENGTH;}

	SAFER_K64_Encryption(const byte *userKey, unsigned int = 0, unsigned int rounds=ROUNDS)
		: SAFER(userKey, userKey, rounds, false) {}

	void ProcessBlock(byte * inoutBlock) const
		{SAFER::Encrypt(inoutBlock, inoutBlock);}
	void ProcessBlock(const byte *inBlock, byte *outBlock) const
		{SAFER::Encrypt(inBlock, outBlock);}
};

class SAFER_K64_Decryption : public SAFER
{
public:
	enum {KEYLENGTH=8, ROUNDS=6};
	static unsigned int KeyLength(unsigned int keylength) {return KEYLENGTH;}

	SAFER_K64_Decryption(const byte *userKey, unsigned int = 0, unsigned int rounds=ROUNDS)
		: SAFER(userKey, userKey, rounds, false) {}

	void ProcessBlock(byte * inoutBlock) const
		{SAFER::Decrypt(inoutBlock, inoutBlock);}
	void ProcessBlock(const byte *inBlock, byte *outBlock) const
		{SAFER::Decrypt(inBlock, outBlock);}
};

class SAFER_K128_Encryption : public SAFER
{
public:
	enum {KEYLENGTH=16, ROUNDS=10};
	static unsigned int KeyLength(unsigned int keylength) {return KEYLENGTH;}

	SAFER_K128_Encryption(const byte *userKey, unsigned int = 0, unsigned int rounds=ROUNDS)
		: SAFER(userKey, userKey+8, rounds, false) {}

	void ProcessBlock(byte * inoutBlock) const
		{SAFER::Encrypt(inoutBlock, inoutBlock);}
	void ProcessBlock(const byte *inBlock, byte *outBlock) const
		{SAFER::Encrypt(inBlock, outBlock);}
};

class SAFER_K128_Decryption : public SAFER
{
public:
	enum {KEYLENGTH=16, ROUNDS=10};
	static unsigned int KeyLength(unsigned int keylength) {return KEYLENGTH;}

	SAFER_K128_Decryption(const byte *userKey, unsigned int = 0, unsigned int rounds=ROUNDS)
		: SAFER(userKey, userKey+8, rounds, false) {}

	void ProcessBlock(byte * inoutBlock) const
		{SAFER::Decrypt(inoutBlock, inoutBlock);}
	void ProcessBlock(const byte *inBlock, byte *outBlock) const
		{SAFER::Decrypt(inBlock, outBlock);}
};

class SAFER_SK64_Encryption : public SAFER
{
public:
	enum {KEYLENGTH=8, ROUNDS=8};
	static unsigned int KeyLength(unsigned int keylength) {return KEYLENGTH;}

	SAFER_SK64_Encryption(const byte *userKey, unsigned int = 0, unsigned int rounds=ROUNDS)
		: SAFER(userKey, userKey, rounds, true) {}

	void ProcessBlock(byte * inoutBlock) const
		{SAFER::Encrypt(inoutBlock, inoutBlock);}
	void ProcessBlock(const byte *inBlock, byte *outBlock) const
		{SAFER::Encrypt(inBlock, outBlock);}
};

class SAFER_SK64_Decryption : public SAFER
{
public:
	enum {KEYLENGTH=8, ROUNDS=8};
	static unsigned int KeyLength(unsigned int keylength) {return KEYLENGTH;}

	SAFER_SK64_Decryption(const byte *userKey, unsigned int = 0, unsigned int rounds=ROUNDS)
		: SAFER(userKey, userKey, rounds, true) {}

	void ProcessBlock(byte * inoutBlock) const
		{SAFER::Decrypt(inoutBlock, inoutBlock);}
	void ProcessBlock(const byte *inBlock, byte *outBlock) const
		{SAFER::Decrypt(inBlock, outBlock);}
};

class SAFER_SK128_Encryption : public SAFER
{
public:
	enum {KEYLENGTH=16, ROUNDS=10};
	static unsigned int KeyLength(unsigned int keylength) {return KEYLENGTH;}

	SAFER_SK128_Encryption(const byte *userKey, unsigned int = 0, unsigned int rounds=ROUNDS)
		: SAFER(userKey, userKey+8, rounds, true) {}

	void ProcessBlock(byte * inoutBlock) const
		{SAFER::Encrypt(inoutBlock, inoutBlock);}
	void ProcessBlock(const byte *inBlock, byte *outBlock) const
		{SAFER::Encrypt(inBlock, outBlock);}
};

class SAFER_SK128_Decryption : public SAFER
{
public:
	enum {KEYLENGTH=16, ROUNDS=10};
	static unsigned int KeyLength(unsigned int keylength) {return KEYLENGTH;}

	SAFER_SK128_Decryption(const byte *userKey, unsigned int = 0, unsigned int rounds=ROUNDS)
		: SAFER(userKey, userKey+8, rounds, true) {}

	void ProcessBlock(byte * inoutBlock) const
		{SAFER::Decrypt(inoutBlock, inoutBlock);}
	void ProcessBlock(const byte *inBlock, byte *outBlock) const
		{SAFER::Decrypt(inBlock, outBlock);}
};

NAMESPACE_END

#endif
