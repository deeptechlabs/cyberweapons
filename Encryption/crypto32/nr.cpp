// nr.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "nr.h"
#include "asn.h"
#include "nbtheory.h"

NAMESPACE_BEGIN(CryptoPP)

NRDigestVerifier::NRDigestVerifier(const Integer &p, const Integer &q,
			   const Integer &g, const Integer &y)
	: m_p(p), m_q(q), m_g(g), m_y(y),
	  m_gpc(p, g, q.BitCount(), 1), m_ypc(p, y, q.BitCount(), 1)
{
}

void NRDigestVerifier::Precompute(unsigned int precomputationStorage)
{
	m_gpc.Precompute(m_p, m_g, ExponentBitLength(), precomputationStorage);
	m_ypc.Precompute(m_p, m_y, ExponentBitLength(), precomputationStorage);
}

void NRDigestVerifier::LoadPrecomputation(BufferedTransformation &bt)
{
	m_gpc.Load(m_p, bt);
	m_ypc.Load(m_p, bt);
}

void NRDigestVerifier::SavePrecomputation(BufferedTransformation &bt) const
{
	m_gpc.Save(bt);
	m_ypc.Save(bt);
}

Integer NRDigestVerifier::EncodeDigest(const byte *digest, unsigned int digestLen) const
{
	Integer h;
	if (digestLen*8 < m_q.BitCount())
		h.Decode(digest, digestLen);
	else
	{
		h.Decode(digest, m_q.ByteCount());
		h >>= m_q.ByteCount()*8 - m_q.BitCount() + 1;
	}
	assert(h < m_q);
	return h;
}

unsigned int NRDigestVerifier::ExponentBitLength() const
{
	return m_q.BitCount();
}

NRDigestVerifier::NRDigestVerifier(BufferedTransformation &bt)
{
	BERSequenceDecoder seq(bt);
	m_p.BERDecode(seq);
	m_q.BERDecode(seq);
	m_g.BERDecode(seq);
	m_y.BERDecode(seq);
	seq.OutputFinished();

	m_gpc.Precompute(m_p, m_g, ExponentBitLength(), 1);
	m_ypc.Precompute(m_p, m_y, ExponentBitLength(), 1);
}

void NRDigestVerifier::DEREncode(BufferedTransformation &bt) const
{
	DERSequenceEncoder seq(bt);
	m_p.DEREncode(seq);
	m_q.DEREncode(seq);
	m_g.DEREncode(seq);
	m_y.DEREncode(seq);
	seq.InputFinished();
}

bool NRDigestVerifier::VerifyDigest(const byte *digest, unsigned int digestLen, const byte *signature) const
{
	assert(digestLen <= MaxDigestLength());

	Integer h = EncodeDigest(digest, digestLen);
	unsigned int qLen = m_q.ByteCount();
	Integer r(signature, qLen);
	Integer s(signature+qLen, qLen);
	return RawVerify(h, r, s);
}

bool NRDigestVerifier::RawVerify(const Integer &m, const Integer &r, const Integer &s) const
{
	if (r>=m_q || r<1 || s>=m_q)
		return false;

	// check r == (m_g^s * m_y^r + m) mod m_q
	return r == (m_gpc.CascadeExponentiate(s, m_ypc, r) + m) % m_q;
}

// ******************************************************************

NRDigestSigner::NRDigestSigner(const Integer &p, const Integer &q, const Integer &g, const Integer &y, const Integer &x)
	: NRDigestVerifier(p, q, g, y), m_x(x)
{
}

NRDigestSigner::NRDigestSigner(RandomNumberGenerator &rng, unsigned int pbits)
{
	PrimeAndGenerator pg(1, rng, pbits, 2*DiscreteLogWorkFactor(pbits));
	m_p = pg.Prime();
	m_q = pg.SubPrime();
	m_g = pg.Generator();
	m_x.Randomize(rng, 2, m_q-2, Integer::ANY);
	m_gpc.Precompute(m_p, m_g, ExponentBitLength(), 1);
	m_y = m_gpc.Exponentiate(m_x);
	m_ypc.Precompute(m_p, m_y, ExponentBitLength(), 1);
}

NRDigestSigner::NRDigestSigner(RandomNumberGenerator &rng, const Integer &pIn, const Integer &qIn, const Integer &gIn)
{
	m_p = pIn;
	m_q = qIn;
	m_g = gIn;
	m_x.Randomize(rng, 2, m_q-2, Integer::ANY);
	m_gpc.Precompute(m_p, m_g, ExponentBitLength(), 1);
	m_y = m_gpc.Exponentiate(m_x);
	m_ypc.Precompute(m_p, m_y, ExponentBitLength(), 1);
}

NRDigestSigner::NRDigestSigner(BufferedTransformation &bt)
{
	BERSequenceDecoder seq(bt);
	m_p.BERDecode(seq);
	m_q.BERDecode(seq);
	m_g.BERDecode(seq);
	m_y.BERDecode(seq);
	m_x.BERDecode(seq);
	seq.OutputFinished();

	m_gpc.Precompute(m_p, m_g, ExponentBitLength(), 1);
	m_ypc.Precompute(m_p, m_y, ExponentBitLength(), 1);
}

void NRDigestSigner::DEREncode(BufferedTransformation &bt) const
{
	DERSequenceEncoder seq(bt);
	m_p.DEREncode(seq);
	m_q.DEREncode(seq);
	m_g.DEREncode(seq);
	m_y.DEREncode(seq);
	m_x.DEREncode(seq);
	seq.InputFinished();
}

void NRDigestSigner::SignDigest(RandomNumberGenerator &rng, const byte *digest, unsigned int digestLen, byte *signature) const
{
	assert(digestLen <= MaxDigestLength());

	Integer h = EncodeDigest(digest, digestLen);
	Integer r;
	Integer s;

	RawSign(rng, h, r, s);
	unsigned int qLen = m_q.ByteCount();
	r.Encode(signature, qLen);
	s.Encode(signature+qLen, qLen);
}

void NRDigestSigner::RawSign(RandomNumberGenerator &rng, const Integer &m, Integer &r, Integer &s) const
{
	do
	{
		Integer k(rng, 2, m_q-2, Integer::ANY);
		r = (m_gpc.Exponentiate(k) + m) % m_q;
		s = (k - m_x*r) % m_q;
	} while (!r);			// make sure r != 0
}

NAMESPACE_END
