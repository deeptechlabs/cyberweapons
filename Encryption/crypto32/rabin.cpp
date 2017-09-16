// rabin.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "rabin.h"
#include "nbtheory.h"
#include "asn.h"
#include "sha.h"

#include "pubkey.cpp"
#include "oaep.cpp"

NAMESPACE_BEGIN(CryptoPP)

INSTANTIATE_PUBKEY_CRYPTO_TEMPLATES_MACRO(OAEP<SHA>, RabinFunction, InvertibleRabinFunction);

RabinFunction::RabinFunction(const Integer &n, const Integer &r, const Integer &s)
	: n(n), r(r), s(s)
{
}

RabinFunction::RabinFunction(BufferedTransformation &bt)
{
	BERSequenceDecoder seq(bt);
	n.BERDecode(seq);
	r.BERDecode(seq);
	s.BERDecode(seq);
	seq.OutputFinished();
}

void RabinFunction::DEREncode(BufferedTransformation &bt) const
{
	DERSequenceEncoder seq(bt);
	n.DEREncode(seq);
	r.DEREncode(seq);
	s.DEREncode(seq);
	seq.InputFinished();
}

Integer RabinFunction::ApplyFunction(const Integer &in) const
{
	Integer out = in.Squared()%n;
	if (in.IsOdd())
		out = out*r%n;
	if (Jacobi(in, n)==-1)
		out = out*s%n;
	return out;
}

// *****************************************************************************
// private key operations:

InvertibleRabinFunction::InvertibleRabinFunction(const Integer &n, const Integer &r, const Integer &s,
								 const Integer &p, const Integer &q, const Integer &u)
	: RabinFunction(n, r, s), p(p), q(q), u(u)
{
	assert(p*q==n);
	assert(Jacobi(r, p) == 1);
	assert(Jacobi(r, q) == -1);
	assert(Jacobi(s, p) == -1);
	assert(Jacobi(s, q) == 1);
	assert(u*q%p==1);
}

// generate a random private key
InvertibleRabinFunction::InvertibleRabinFunction(RandomNumberGenerator &rng, unsigned int keybits)
{
	assert(keybits >= 16);
	// generate 2 random primes of suitable size
	if (keybits%2==0)
	{
		const Integer minP = Integer(182) << (keybits/2-8);
		const Integer maxP = Integer::Power2(keybits/2)-1;
		p.Randomize(rng, minP, maxP, Integer::PRIME, 3, 4);
		q.Randomize(rng, minP, maxP, Integer::PRIME, 3, 4);
	}
	else
	{
		const Integer minP = Integer::Power2((keybits-1)/2);
		const Integer maxP = Integer(181) << ((keybits+1)/2-8);
		p.Randomize(rng, minP, maxP, Integer::PRIME, 3, 4);
		q.Randomize(rng, minP, maxP, Integer::PRIME, 3, 4);
	}

	bool rFound=false, sFound=false;
	Integer t=2;
	while (!(rFound && sFound))
	{
		int jp = Jacobi(t, p);
		int jq = Jacobi(t, q);

		if (!rFound && jp==1 && jq==-1)
		{
			r = t;
			rFound = true;
		}

		if (!sFound && jp==-1 && jq==1)
		{
			s = t;
			sFound = true;
		}

		++t;
	}

	n = p * q;
	assert(n.BitCount() == keybits);
	u = EuclideanMultiplicativeInverse(q, p);
	assert(u*q%p==1);
}

InvertibleRabinFunction::InvertibleRabinFunction(BufferedTransformation &bt)
{
	BERSequenceDecoder seq(bt);
	n.BERDecode(seq);
	r.BERDecode(seq);
	s.BERDecode(seq);
	p.BERDecode(seq);
	q.BERDecode(seq);
	u.BERDecode(seq);
	seq.OutputFinished();
}

void InvertibleRabinFunction::DEREncode(BufferedTransformation &bt) const
{
	DERSequenceEncoder seq(bt);
	n.DEREncode(seq);
	r.DEREncode(seq);
	s.DEREncode(seq);
	p.DEREncode(seq);
	q.DEREncode(seq);
	u.DEREncode(seq);
	seq.InputFinished();
}

Integer InvertibleRabinFunction::CalculateInverse(const Integer &in) const
{
	Integer cp=in%p, cq=in%q;

	int jp = Jacobi(cp, p);
	int jq = Jacobi(cq, q);

	if (jq==-1)
	{
		cp = cp*EuclideanMultiplicativeInverse(r, p)%p;
		cq = cq*EuclideanMultiplicativeInverse(r, q)%q;
	}

	if (jp==-1)
	{
		cp = cp*EuclideanMultiplicativeInverse(s, p)%p;
		cq = cq*EuclideanMultiplicativeInverse(s, q)%q;
	}

	cp = ModularSquareRoot(cp, p);
	cq = ModularSquareRoot(cq, q);

	if (jp==-1)
		cp = p-cp;

	Integer out = CRT(cq, q, cp, p, u);

	if ((jq==-1 && out.IsEven()) || (jq==1 && out.IsOdd()))
		out = n-out;

	return out;
}

NAMESPACE_END
