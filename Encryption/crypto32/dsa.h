#ifndef CRYPTOPP_DSA_H
#define CRYPTOPP_DSA_H

#include "pubkey.h"
#include "modexppc.h"
#include "sha.h"

#include <limits.h>

NAMESPACE_BEGIN(CryptoPP)

// GDSA stands for generalized DSA, where the key length is allowed
// to be greater than 1024 and any message digest function can be used.
// Standard DSA is at the bottom of this file.

class GDSADigestVerifier : public PK_WithPrecomputation<DigestVerifier>
{
public:
	GDSADigestVerifier(const Integer &p, const Integer &q, const Integer &g, const Integer &y);
	GDSADigestVerifier(BufferedTransformation &bt);

	void Precompute(unsigned int precomputationStorage=16);
	void LoadPrecomputation(BufferedTransformation &storedPrecomputation);
	void SavePrecomputation(BufferedTransformation &storedPrecomputation) const;

	void DEREncode(BufferedTransformation &bt) const;
	bool VerifyDigest(const byte *digest, unsigned int digestLen, const byte *signature) const;

	unsigned int MaxDigestLength() const {return UINT_MAX;}
	unsigned int DigestSignatureLength() const {return 2*m_q.ByteCount();}

	const Integer & GetModulus() const {return m_p;}
	const Integer & GetSubgroupSize() const {return m_q;}
	const Integer & GetGenerator() const {return m_g;}
	const Integer & GetPublicResidue() const {return m_y;}

	// exposed for validation testing
	bool RawVerify(const Integer &m, const Integer &a, const Integer &b) const;

protected:
	GDSADigestVerifier() {}
	unsigned int ExponentBitLength() const;
	Integer EncodeDigest(const byte *digest, unsigned int digestLen) const;

	Integer m_p, m_q, m_g, m_y;
	ModExpPrecomputation m_gpc, m_ypc;
};

class GDSADigestSigner : public GDSADigestVerifier, public PK_WithPrecomputation<DigestSigner>
{
public:
	GDSADigestSigner(const Integer &p, const Integer &q, const Integer &g, const Integer &y, const Integer &x);
	GDSADigestSigner(RandomNumberGenerator &rng, unsigned int pbits);
	GDSADigestSigner(RandomNumberGenerator &rng, const Integer &p, const Integer &q, const Integer &g);
	GDSADigestSigner(BufferedTransformation &bt);

	void DEREncode(BufferedTransformation &bt) const;
	void SignDigest(RandomNumberGenerator &rng, const byte *digest, unsigned int digestLen, byte *signature) const;

	const Integer & GetPrivateExponent() const {return m_x;}

	// exposed for validation testing
	void RawSign(const Integer &k, const Integer &h, Integer &r, Integer &s) const;

protected:
	GDSADigestSigner() {}

	Integer m_x;
};

template <class H>
class GDSASigner : public SignerTemplate<GDSADigestSigner, H>, public PK_WithPrecomputation<PK_Signer>
{
	typedef SignerTemplate<GDSADigestSigner, H> Base;
public:
	GDSASigner(const Integer &p, const Integer &q, const Integer &g, const Integer &y, const Integer &x)
		: Base(GDSADigestSigner(p, q, g, y, x)) {}

	// generate a random private key
	GDSASigner(RandomNumberGenerator &rng, unsigned int keybits)
		: Base(GDSADigestSigner(rng, keybits)) {}

	// generate a random private key, given p, q, and g
	GDSASigner(RandomNumberGenerator &rng, const Integer &p, const Integer &q, const Integer &g)
		: Base(GDSADigestSigner(rng, p, q, g)) {}

	// load a previously generated key
	GDSASigner(BufferedTransformation &storedKey)
		: Base(storedKey) {}

protected:
	GDSASigner() {}
};

template <class H>
class GDSAVerifier : public VerifierTemplate<GDSADigestVerifier, H>, public PK_WithPrecomputation<PK_Verifier>
{
	typedef VerifierTemplate<GDSADigestVerifier, H> Base;
public:
	GDSAVerifier(const Integer &p, const Integer &q, const Integer &g, const Integer &y)
		: Base(GDSADigestVerifier(p, q, g, y)) {}

	// create a matching public key from a private key
	GDSAVerifier(const GDSASigner<H> &priv)
		: Base(priv) {}

	// load a previously generated key
	GDSAVerifier(BufferedTransformation &storedKey)
		: Base(storedKey) {}
};

// ***********************************************************

const int MIN_DSA_PRIME_LENGTH = 512;
const int MAX_DSA_PRIME_LENGTH = 1024;

// both seedLength and primeLength are in bits, but seedLength should
// be a multiple of 8
bool GenerateDSAPrimes(byte *seed, unsigned int seedLength, int &counter,
						  Integer &p, unsigned int primeLength, Integer &q);

class SHA;

class DSAPrivateKey : public GDSASigner<SHA>
{
public:
	DSAPrivateKey(const Integer &p, const Integer &q, const Integer &g, const Integer &y, const Integer &x)
		: GDSASigner<SHA>(p, q, g, y, x) {}

	// generate a random private key
	// keybits must be between 512 and 1024, and divisible by 64
	DSAPrivateKey(RandomNumberGenerator &rng, unsigned int keybits);

	// generate a random private key, given p, q, and g
	DSAPrivateKey(RandomNumberGenerator &rng, const Integer &p, const Integer &q, const Integer &g)
		: GDSASigner<SHA>(rng, p, q, g) {}

	// load a previously generated key
	DSAPrivateKey(BufferedTransformation &storedKey)
		: GDSASigner<SHA>(storedKey) {}
};

typedef GDSAVerifier<SHA> DSAPublicKey;

NAMESPACE_END

#endif
