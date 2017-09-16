#ifndef CRYPTOPP_SAPPHIRE_H
#define CRYPTOPP_SAPPHIRE_H

#include "cryptlib.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

class SapphireBase
{
public:
	enum {KEYLENGTH=16};    // default key length

protected:
	SapphireBase();
	SapphireBase(const byte *userKey, unsigned int keyLength);
	~SapphireBase();

	inline void ShuffleCards()
	{
		ratchet += cards[rotor++];
		byte swaptemp = cards[last_cipher];
		cards[last_cipher] = cards[ratchet];
		cards[ratchet] = cards[last_plain];
		cards[last_plain] = cards[rotor];
		cards[rotor] = swaptemp;
		avalanche += cards[swaptemp];
	}

	// These variables comprise the state of the state machine.

	SecByteBlock cards;             // A permutation of 0-255.
	byte rotor,                     // Index that rotates smoothly
		 ratchet,                   // Index that moves erratically
		 avalanche,                 // Index heavily data dependent
		 last_plain,                // Last plain text byte
		 last_cipher;               // Last cipher text byte

private:
	byte keyrand(unsigned int limit, const byte *user_key, byte keysize, byte *rsum, unsigned *keypos);
};

class SapphireEncryption : public StreamCipher, protected SapphireBase
{
public:
	SapphireEncryption(const byte *userKey, unsigned int keyLength=KEYLENGTH)
		: SapphireBase(userKey, keyLength) {}

	inline byte ProcessByte(byte b)
	{
		ShuffleCards();
		last_cipher = b^cards[(cards[ratchet] + cards[rotor]) & 0xFF] ^
					  cards[cards[(cards[last_plain] +
								   cards[last_cipher] +
								   cards[avalanche])&0xFF]];
		last_plain = b;
		return last_cipher;
	}

	void ProcessString(byte *outString, const byte *inString, unsigned int length);
	void ProcessString(byte *inoutString, unsigned int length);

protected:
	SapphireEncryption() {}     // for SapphireHash
};

class SapphireDecryption : public StreamCipher, private SapphireBase
{
public:
	SapphireDecryption(const byte *userKey, unsigned int keyLength=KEYLENGTH)
		: SapphireBase(userKey, keyLength) {}

	inline byte ProcessByte(byte b)
	{
		ShuffleCards();
		last_plain = b^cards[(cards[ratchet] + cards[rotor]) & 0xFF] ^
					   cards[cards[(cards[last_plain] +
									cards[last_cipher] +
									cards[avalanche])&0xFF]];
		last_cipher = b;
		return last_plain;
	}

	void ProcessString(byte *outString, const byte *inString, unsigned int length);
	void ProcessString(byte *inoutString, unsigned int length);
};

class SapphireRNG : public RandomNumberGenerator, private SapphireEncryption
{
public:
	SapphireRNG(const byte *seed, unsigned int seedLength)
		: SapphireEncryption(seed, seedLength) {}

	inline byte GetByte() {return SapphireEncryption::ProcessByte(0);}
};

class SapphireHash : public HashModule, private SapphireEncryption
{
public:
	SapphireHash(unsigned int hashLength=20);
	void Update(const byte *input, unsigned int length);
	void Final(byte *hash) {Final(hash, hashLength);}
	void Final(byte *hash, unsigned int overrideHashLength);
	unsigned int DigestSize() const {return hashLength;}

private:
	const unsigned int hashLength;
};

NAMESPACE_END

#endif
