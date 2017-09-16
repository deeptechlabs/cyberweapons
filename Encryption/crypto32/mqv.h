#ifndef CRYPTOPP_MQV_H
#define CRYPTOPP_MQV_H

#include "modexppc.h"

NAMESPACE_BEGIN(CryptoPP)

// Menezes-Qu-Vanstone in GF(p) with key validation

class MQV : public PK_WithPrecomputation<PK_AuthenticatedKeyAgreementDomain>
{
public:
	MQV(const Integer &p, const Integer &q, const Integer &g);
	MQV(RandomNumberGenerator &rng, unsigned int pbits);
	MQV(BufferedTransformation &domainParams);

	void DEREncode(BufferedTransformation &domainParams) const;

	void Precompute(unsigned int precomputationStorage=16);
	void LoadPrecomputation(BufferedTransformation &storedPrecomputation);
	void SavePrecomputation(BufferedTransformation &storedPrecomputation) const;

	bool ValidateDomainParameters(RandomNumberGenerator &rng) const;
	unsigned int AgreedValueLength() const {return p.ByteCount();}

	unsigned int StaticPrivateKeyLength() const {return q.ByteCount();}
	unsigned int StaticPublicKeyLength() const {return p.ByteCount();}
	void GenerateStaticKeyPair(RandomNumberGenerator &rng, byte *privateKey, byte *publicKey) const;

	unsigned int EphemeralPrivateKeyLength() const {return p.ByteCount()+q.ByteCount();}
	unsigned int EphemeralPublicKeyLength() const {return p.ByteCount();}
	void GenerateEphemeralKeyPair(RandomNumberGenerator &rng, byte *privateKey, byte *publicKey) const;

	bool Agree(byte *agreedValue,
		const byte *staticPrivateKey, const byte *ephemeralPrivateKey, 
		const byte *staticOtherPublicKey, const byte *ephemeralOtherPublicKey,
		bool validateStaticOtherPublicKey=true) const;

	const Integer &Prime() const {return p;}
	const Integer &SubPrime() const {return q;}
	const Integer &Generator() const {return g;}

private:
	unsigned int ExponentBitLength() const;

	Integer p, q, g;
	ModExpPrecomputation gpc;
};

NAMESPACE_END

#endif
