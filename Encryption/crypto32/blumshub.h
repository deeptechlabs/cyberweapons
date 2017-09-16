#ifndef CRYPTOPP_BLUMSHUB_H
#define CRYPTOPP_BLUMSHUB_H

#include "cryptlib.h"
#include "modarith.h"

NAMESPACE_BEGIN(CryptoPP)

class BlumGoldwasserPublicKey;
class BlumGoldwasserPrivateKey;

class PublicBlumBlumShub : public RandomNumberGenerator,
						   public virtual StreamCipher
{
public:
	PublicBlumBlumShub(const Integer &n, const Integer &seed);

	unsigned int GetBit();
	byte GetByte();

	byte ProcessByte(byte input)
		{return (input ^ GetByte());}

protected:
	const ModularArithmetic modn;
	const int maxBits;
	Integer current;
	int bitsLeft;

	friend class BlumGoldwasserPublicKey;
	friend class BlumGoldwasserPrivateKey;
};

class BlumBlumShub : public PublicBlumBlumShub,
					 public RandomAccessStreamCipher
{
public:
	// Make sure p and q are both primes congruent to 3 mod 4 and at least 512 bits long,
	// seed is the secret key and should be about as big as p*q
	BlumBlumShub(const Integer &p, const Integer &q, const Integer &seed);
	void Seek(unsigned long index);

protected:
	const Integer p, q;
	const Integer x0;
};

NAMESPACE_END

#endif
