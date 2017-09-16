#ifndef CRYPTOPP_IDEA_H
#define CRYPTOPP_IDEA_H

#include "cryptlib.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

class IDEA : public BlockTransformation
{
public:
	IDEA(const byte *userKey, CipherDir dir);

	void ProcessBlock(byte * inoutBlock) const
		{IDEA::ProcessBlock(inoutBlock, inoutBlock);}
	void ProcessBlock(const byte *inBlock, byte * outBlock) const;

	enum {KEYLENGTH=16, BLOCKSIZE=8, ROUNDS=8};
	unsigned int BlockSize() const {return BLOCKSIZE;};
	static unsigned int KeyLength(unsigned int keylength) {return KEYLENGTH;}

private:
	void EnKey(const byte *);
	void DeKey();
	SecBlock<word> key;

#ifdef IDEA_LARGECACHE
	static inline void LookupMUL(word &a, word b);
	void LookupKeyLogs();
	static void BuildLogTables();
	static bool tablesBuilt;
	static word16 log[0x10000], antilog[0x10000];
#endif
};

class IDEAEncryption : public IDEA
{
public:
	IDEAEncryption(const byte * userKey, unsigned int = 0)
		: IDEA (userKey, ENCRYPTION) {}
};

class IDEADecryption : public IDEA
{
public:
	IDEADecryption(const byte * userKey, unsigned int = 0)
		: IDEA (userKey, DECRYPTION) {}
};

NAMESPACE_END

#endif
