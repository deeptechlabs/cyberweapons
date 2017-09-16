#ifndef CRYPTOPP_BLUMGOLD_H
#define CRYPTOPP_BLUMGOLD_H

#include "cryptlib.h"
#include "integer.h"

NAMESPACE_BEGIN(CryptoPP)

class BlumGoldwasserPublicKey : public PK_Encryptor
{
public:
	// you can use the default copy constructor to make a BlumGoldwasserPublicKey
	// out of a BlumGoldwasserPrivateKey
	BlumGoldwasserPublicKey(const Integer &n);
	BlumGoldwasserPublicKey(BufferedTransformation &bt);

	void DEREncode(BufferedTransformation &bt) const;

	void Encrypt(RandomNumberGenerator &rng, const byte *plainText, unsigned int plainTextLength, byte *cipherText);

	unsigned int MaxPlainTextLength(unsigned int cipherTextLength) const;
	unsigned int CipherTextLength(unsigned int plainTextLength) const;

protected:
	BlumGoldwasserPublicKey() {}

	Integer n;           // these are only modified in constructors
	unsigned int modulusLen;
};

class BlumGoldwasserPrivateKey : public BlumGoldwasserPublicKey, public PK_Decryptor
{
public:
	BlumGoldwasserPrivateKey(const Integer &n, const Integer &p, const Integer &q, const Integer &u);
	// generate a random private key
	BlumGoldwasserPrivateKey(RandomNumberGenerator &rng, unsigned int keybits);
	BlumGoldwasserPrivateKey(BufferedTransformation &bt);

	void DEREncode(BufferedTransformation &bt) const;

	unsigned int Decrypt(const byte *cipherText, unsigned int cipherTextLength, byte *plainText);

protected:
	Integer p, q, u;
};

NAMESPACE_END

#endif
