// rsa.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "rsa.h"
#include "asn.h"
#include "nbtheory.h"
#include "sha.h"

#include "pubkey.cpp"
#include "oaep.cpp"

NAMESPACE_BEGIN(CryptoPP)

INSTANTIATE_PUBKEY_TEMPLATES_MACRO(PKCS_EncryptionPaddingScheme, PKCS_SignaturePaddingScheme, RSAFunction, InvertibleRSAFunction);
template class OAEP<SHA>;
INSTANTIATE_PUBKEY_CRYPTO_TEMPLATES_MACRO(OAEP<SHA>, RSAFunction, InvertibleRSAFunction);

RSAFunction::RSAFunction(BufferedTransformation &bt)
{
	BERSequenceDecoder seq(bt);
	n.BERDecode(seq);
	e.BERDecode(seq);
	seq.OutputFinished();
}

void RSAFunction::DEREncode(BufferedTransformation &bt) const
{
	DERSequenceEncoder seq(bt);
	n.DEREncode(seq);
	e.DEREncode(seq);
	seq.InputFinished();
}

Integer RSAFunction::ApplyFunction(const Integer &x) const
{
	return a_exp_b_mod_c(x, e, n);
}

// *****************************************************************************

InvertibleRSAFunction::InvertibleRSAFunction(const Integer &n, const Integer &e, const Integer &d,
	const Integer &p, const Integer &q, const Integer &dp, const Integer &dq, const Integer &u)
		: RSAFunction(n, e), d(d), p(p), q(q), dp(dp), dq(dq), u(u)
{
	assert(p*q==n);
	assert(d*e%LCM(p-1, q-1)==1);
	assert(dp==d%(p-1));
	assert(dq==d%(q-1));
	assert(u*q%p==1);
}

// generate a random private key
InvertibleRSAFunction::InvertibleRSAFunction(RandomNumberGenerator &rng, unsigned int keybits, const Integer &eStart)
{
	assert(keybits >= 16);
	// generate 2 random primes of suitable size
	if (keybits%2==0)
	{
		const Integer minP = Integer(182) << (keybits/2-8);
		const Integer maxP = Integer::Power2(keybits/2)-1;
		p.Randomize(rng, minP, maxP, Integer::PRIME);
		q.Randomize(rng, minP, maxP, Integer::PRIME);
	}
	else
	{
		const Integer minP = Integer::Power2((keybits-1)/2);
		const Integer maxP = Integer(181) << ((keybits+1)/2-8);
		p.Randomize(rng, minP, maxP, Integer::PRIME);
		q.Randomize(rng, minP, maxP, Integer::PRIME);
	}

	// pre-calculate some other data for faster speed
	const Integer lcm = LCM(p-1, q-1);
	// make sure e starts odd
	for (e = eStart+(1-eStart%2); GCD(e, lcm)!=1; ++e, ++e);
	d = EuclideanMultiplicativeInverse(e, lcm);
	dp = d % (p-1);
	dq = d % (q-1);
	u = EuclideanMultiplicativeInverse(q, p);
	n = p * q;
	assert(n.BitCount() == keybits);
}

InvertibleRSAFunction::InvertibleRSAFunction(BufferedTransformation &bt)
{
	BERSequenceDecoder seq(bt);
	word32 version;
	BERDecodeUnsigned<word32>(seq, version, INTEGER, 0, 0);	// check version
	n.BERDecode(seq);
	e.BERDecode(seq);
	d.BERDecode(seq);
	p.BERDecode(seq);
	q.BERDecode(seq);
	dp.BERDecode(seq);
	dq.BERDecode(seq);
	u.BERDecode(seq);
	seq.OutputFinished();
}

void InvertibleRSAFunction::DEREncode(BufferedTransformation &bt) const
{
	DERSequenceEncoder seq(bt);
	DEREncodeUnsigned<word32>(0, seq);	// version
	n.DEREncode(seq);
	e.DEREncode(seq);
	d.DEREncode(seq);
	p.DEREncode(seq);
	q.DEREncode(seq);
	dp.DEREncode(seq);
	dq.DEREncode(seq);
	u.DEREncode(seq);
	seq.InputFinished();
}

Integer InvertibleRSAFunction::CalculateInverse(const Integer &x) const 
{
	// here we follow the notation of PKCS #1 and let u=q inverse mod p
	// but in ModRoot, u=p inverse mod q, so we reverse the order of p and q
	return ModularRoot(x, dq, dp, q, p, u);
}

NAMESPACE_END
