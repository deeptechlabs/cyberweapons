#ifndef CRYPTOPP_NR_H
#define CRYPTOPP_NR_H

#include "pubkey.h"
#include "modexppc.h"

#include <limits.h>

NAMESPACE_BEGIN(CryptoPP)

class NRDigestVerifier : public PK_WithPrecomputation<DigestVerifier>
{
public:
	NRDigestVerifier(const Integer &p, const Integer &q, const Integer &g, const Integer &y);
	NRDigestVerifier(BufferedTransformation &bt);

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

protected:
	NRDigestVerifier() {}
	bool RawVerify(const Integer &m, const Integer &a, const Integer &b) const;
	unsigned int ExponentBitLength() const;
	Integer EncodeDigest(const byte *digest, unsigned int digestLen) const;

	Integer m_p, m_q, m_g, m_y;
	ModExpPrecomputation m_gpc, m_ypc;
};

class NRDigestSigner : public NRDigestVerifier, public PK_WithPrecomputation<DigestSigner>
{
public:
	NRDigestSigner(const Integer &p, const Integer &q, const Integer &g, const Integer &y, const Integer &x);
	NRDigestSigner(RandomNumberGenerator &rng, unsigned int pbits);
	NRDigestSigner(RandomNumberGenerator &rng, const Integer &p, const Integer &q, const Integer &g);
	NRDigestSigner(BufferedTransformation &bt);

	void DEREncode(BufferedTransformation &bt) const;
	void SignDigest(RandomNumberGenerator &rng, const byte *digest, unsigned int digestLen, byte *signature) const;

	const Integer & GetPrivateExponent() const {return m_x;}

protected:
	void RawSign(RandomNumberGenerator &rng, const Integer &m, Integer &a, Integer &b) const;

	Integer m_x;
};

template <class H>
class NRSigner : public SignerTemplate<NRDigestSigner, H>, public PK_WithPrecomputation<PK_Signer>
{
	typedef SignerTemplate<NRDigestSigner, H> Base;
public:
	NRSigner(const Integer &p, const Integer &q, const Integer &g, const Integer &y, const Integer &x)
		: Base(NRDigestSigner(p, q, g, y, x)) {}

	// generate a random private key
	NRSigner(RandomNumberGenerator &rng, unsigned int keybits)
		: Base(NRDigestSigner(rng, keybits)) {}

	// generate a random private key, given p, q, and g
	NRSigner(RandomNumberGenerator &rng, const Integer &p, const Integer &q, const Integer &g)
		: Base(NRDigestSigner(rng, p, q, g)) {}

	// load a previously generated key
	NRSigner(BufferedTransformation &storedKey)
		: Base(storedKey) {}
};

template <class H>
class NRVerifier : public VerifierTemplate<NRDigestVerifier, H>, public PK_WithPrecomputation<PK_Verifier>
{
	typedef VerifierTemplate<NRDigestVerifier, H> Base;
public:
	NRVerifier(const Integer &p, const Integer &q, const Integer &g, const Integer &y)
		: Base(NRDigestVerifier(p, q, g, y)) {}

	// create a matching public key from a private key
	NRVerifier(const NRSigner<H> &priv)
		: Base(priv) {}

	// load a previously generated key
	NRVerifier(BufferedTransformation &storedKey)
		: Base(storedKey) {}
};

NAMESPACE_END

#endif
