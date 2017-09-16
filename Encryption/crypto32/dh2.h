#ifndef CRYPTOPP_DH2_H
#define CRYPTOPP_DH2_H

#include "cryptlib.h"

NAMESPACE_BEGIN(CryptoPP)

class DH2 : public PK_AuthenticatedKeyAgreementDomain
{
public:
	DH2(const PK_SimpleKeyAgreementDomain &domain)
		: d1(domain), d2(domain) {}
	DH2(const PK_SimpleKeyAgreementDomain &staticDomain, const PK_SimpleKeyAgreementDomain &ephemeralDomain)
		: d1(staticDomain), d2(ephemeralDomain) {}

	bool ValidateDomainParameters(RandomNumberGenerator &rng) const
		{return d1.ValidateDomainParameters(rng) && d2.ValidateDomainParameters(rng);}
	unsigned int AgreedValueLength() const
		{return d1.AgreedValueLength() + d2.AgreedValueLength();}

	unsigned int StaticPrivateKeyLength() const
		{return d1.PrivateKeyLength();}
	unsigned int StaticPublicKeyLength() const
		{return d1.PublicKeyLength();}
	void GenerateStaticKeyPair(RandomNumberGenerator &rng, byte *privateKey, byte *publicKey) const
		{d1.GenerateKeyPair(rng, privateKey, publicKey);}

	unsigned int EphemeralPrivateKeyLength() const
		{return d2.PrivateKeyLength();}
	unsigned int EphemeralPublicKeyLength() const
		{return d2.PublicKeyLength();}
	void GenerateEphemeralKeyPair(RandomNumberGenerator &rng, byte *privateKey, byte *publicKey) const
		{d2.GenerateKeyPair(rng, privateKey, publicKey);}

	bool Agree(byte *agreedValue,
		const byte *staticPrivateKey, const byte *ephemeralPrivateKey, 
		const byte *staticOtherPublicKey, const byte *ephemeralOtherPublicKey,
		bool validateStaticOtherPublicKey=true) const;

protected:
	const PK_SimpleKeyAgreementDomain &d1, &d2;
};

NAMESPACE_END

#endif
