#ifndef CRYPTOPP_ELGAMAL_H
#define CRYPTOPP_ELGAMAL_H

#include "modexppc.h"

NAMESPACE_BEGIN(CryptoPP)

class ElGamalEncryptor : public PK_WithPrecomputation<PK_FixedLengthEncryptor>
{
public:
	ElGamalEncryptor(const Integer &p, const Integer &g, const Integer &y);
	ElGamalEncryptor(BufferedTransformation &bt);

	void DEREncode(BufferedTransformation &bt) const;

	void Precompute(unsigned int precomputationStorage=16);
	void LoadPrecomputation(BufferedTransformation &storedPrecomputation);
	void SavePrecomputation(BufferedTransformation &storedPrecomputation) const;

	void Encrypt(RandomNumberGenerator &rng, const byte *plainText, unsigned int plainTextLength, byte *cipherText);

	unsigned int MaxPlainTextLength() const {return STDMIN(255U, modulusLen-3);}
	unsigned int CipherTextLength() const {return 2*modulusLen;}

	void RawEncrypt(const Integer &k, const Integer &m, Integer &a, Integer &b) const;

	const Integer & GetModulus() const {return p;}
	const Integer & GetGenerator() const {return g;}
	const Integer & GetPublicResidue() const {return y;}

	const ModExpPrecomputation & GetGPC() const {return gpc;}
	const ModExpPrecomputation & GetYPC() const {return ypc;}

protected:
	ElGamalEncryptor() {}
	unsigned int ExponentBitLength() const;

	Integer p, g, y;
	unsigned int modulusLen;
	ModExpPrecomputation gpc, ypc;
};

class ElGamalDecryptor : public ElGamalEncryptor, public PK_FixedLengthDecryptor
{
public:
	ElGamalDecryptor(const Integer &p, const Integer &g, const Integer &y, const Integer &x);
	ElGamalDecryptor(RandomNumberGenerator &rng, unsigned int pbits);
	// generate a random private key, given p and g
	ElGamalDecryptor(RandomNumberGenerator &rng, const Integer &p, const Integer &g);

	ElGamalDecryptor(BufferedTransformation &bt);
	void DEREncode(BufferedTransformation &bt) const;

	unsigned int Decrypt(const byte *cipherText, byte *plainText);

	void RawDecrypt(const Integer &a, const Integer &b, Integer &m) const;

protected:
	Integer x;
};

NAMESPACE_END

#endif
