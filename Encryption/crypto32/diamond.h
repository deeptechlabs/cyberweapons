#ifndef CRYPTOPP_DIAMOND_H
#define CRYPTOPP_DIAMOND_H

#include "cryptlib.h"
#include "misc.h"
#include "crc.h"

NAMESPACE_BEGIN(CryptoPP)

class Diamond2Base : public BlockTransformation
{
public:
	Diamond2Base(const byte *key, unsigned int key_size, unsigned int rounds,
				CipherDir direction);

	enum {KEYLENGTH=16, BLOCKSIZE=16, ROUNDS=10, MAX_KEYLENGTH=256};
	unsigned int BlockSize() const {return BLOCKSIZE;}
	static unsigned int KeyLength(unsigned int keylength)
		{return keylength < 1 ? 1 : (keylength <= MAX_KEYLENGTH ? keylength : MAX_KEYLENGTH);}

protected:
	enum {ROUNDSIZE=4096};
	inline void substitute(int round, byte *y) const;

	const int numrounds;
	SecByteBlock s;         // Substitution boxes

	static inline void permute(byte *);
	static inline void ipermute(byte *);
#ifdef DIAMOND_USE_PERMTABLE
	static const word32 permtable[9][256];
	static const word32 ipermtable[9][256];
#endif
};

class Diamond2Encryption : public Diamond2Base
{
public:
	Diamond2Encryption(const byte *key, unsigned int key_size=KEYLENGTH, unsigned int rounds=ROUNDS)
		: Diamond2Base(key, key_size, rounds, ENCRYPTION) {}

	void ProcessBlock(const byte *inBlock, byte * outBlock) const;
	void ProcessBlock(byte * inoutBlock) const;
};

class Diamond2Decryption : public Diamond2Base
{
public:
	Diamond2Decryption(const byte *key, unsigned int key_size=KEYLENGTH, unsigned int rounds=ROUNDS)
		: Diamond2Base(key, key_size, rounds, DECRYPTION) {}

	void ProcessBlock(const byte *inBlock, byte * outBlock) const;
	void ProcessBlock(byte * inoutBlock) const;
};

class Diamond2LiteBase : public BlockTransformation
{
public:
	Diamond2LiteBase(const byte *key, unsigned int key_size, unsigned int rounds,
				CipherDir direction);

	enum {KEYLENGTH=16, BLOCKSIZE=8, ROUNDS=8, MAX_KEYLENGTH=256};
	unsigned int BlockSize() const {return BLOCKSIZE;}
	static unsigned int KeyLength(unsigned int keylength)
		{return keylength < 1 ? 1 : (keylength <= MAX_KEYLENGTH ? keylength : MAX_KEYLENGTH);}

protected:
	enum {ROUNDSIZE=2048};
	inline void substitute(int round, byte *y) const;
	const int numrounds;
	SecByteBlock s;         // Substitution boxes

	static inline void permute(byte *);
	static inline void ipermute(byte *);
#ifdef DIAMOND_USE_PERMTABLE
	static const word32 permtable[8][256];
	static const word32 ipermtable[8][256];
#endif
};

class Diamond2LiteEncryption : public Diamond2LiteBase
{
public:
	Diamond2LiteEncryption(const byte *key, unsigned int key_size=KEYLENGTH, unsigned int rounds=ROUNDS)
		: Diamond2LiteBase(key, key_size, rounds, ENCRYPTION) {}

	void ProcessBlock(const byte *inBlock, byte * outBlock) const;
	void ProcessBlock(byte * inoutBlock) const;
};

class Diamond2LiteDecryption : public Diamond2LiteBase
{
public:
	Diamond2LiteDecryption(const byte *key, unsigned int key_size=KEYLENGTH, unsigned int rounds=ROUNDS)
		: Diamond2LiteBase(key, key_size, rounds, DECRYPTION) {}

	void ProcessBlock(const byte *inBlock, byte * outBlock) const;
	void ProcessBlock(byte * inoutBlock) const;
};

NAMESPACE_END

#endif
