#ifndef CRYPTOPP_DH_H
#define CRYPTOPP_DH_H

#include "modexppc.h"

NAMESPACE_BEGIN(CryptoPP)

// Diffie-Hellman in GF(p) with key validation

class DH : public PK_WithPrecomputation<PK_SimpleKeyAgreementDomain>
{
public:
	DH(const Integer &p, const Integer &g);
	DH(RandomNumberGenerator &rng, unsigned int pbits);
	DH(BufferedTransformation &domainParams);

	void DEREncode(BufferedTransformation &domainParams) const;

	void Precompute(unsigned int precomputationStorage=16);
	void LoadPrecomputation(BufferedTransformation &storedPrecomputation);
	void SavePrecomputation(BufferedTransformation &storedPrecomputation) const;

	bool ValidateDomainParameters(RandomNumberGenerator &rng) const;
	unsigned int AgreedValueLength() const {return p.ByteCount();}
	unsigned int PrivateKeyLength() const {return p.ByteCount();}
	unsigned int PublicKeyLength() const {return p.ByteCount();}

	void GenerateKeyPair(RandomNumberGenerator &rng, byte *privateKey, byte *publicKey) const;
	bool Agree(byte *agreedValue, const byte *privateKey, const byte *otherPublicKey, bool validateOtherPublicKey=true) const;

	const Integer &GetPrime() const {return p;}
	const Integer &GetGenerator() const {return g;}

private:
	unsigned int ExponentBitLength() const;

	Integer p, g;
	ModExpPrecomputation gpc;
};

NAMESPACE_END

#endif
