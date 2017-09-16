// rw.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "rw.h"
#include "nbtheory.h"
#include "asn.h"

#include "pubkey.cpp"

NAMESPACE_BEGIN(CryptoPP)

template<> const byte EMSA2DigestDecoration<SHA>::decoration = 0x33;
template<> const byte EMSA2DigestDecoration<RIPEMD160>::decoration = 0x31;

template class DigestSignerTemplate<EMSA2Pad, InvertibleRWFunction<IFSSA_R> >;
template class DigestVerifierTemplate<EMSA2Pad, RWFunction<IFSSA_R> >;

void EMSA2Pad::Pad(RandomNumberGenerator &, const byte *input, unsigned int inputLen, byte *emsa2Block, unsigned int emsa2BlockLen) const
{
	assert (inputLen > 0 && inputLen <= MaxUnpaddedLength(emsa2BlockLen));

	// convert from bit length to byte length
	emsa2BlockLen++;
	if (emsa2BlockLen % 8 > 1)
	{
		emsa2Block[0] = 0;
		emsa2Block++;
	}
	emsa2BlockLen /= 8;

	emsa2Block[0] = input[0];			// indicate empty or non-empty message
	memset(emsa2Block+1, 0xbb, emsa2BlockLen-inputLen-2);	// padd with 0xbb
	emsa2Block[emsa2BlockLen-inputLen-1] = 0xba;	// separator
	memcpy(emsa2Block+emsa2BlockLen-inputLen, input+1, inputLen-1);
	emsa2Block[emsa2BlockLen-1] = 0xcc;	// make it congruent to 12 mod 16
}

unsigned int EMSA2Pad::Unpad(const byte *emsa2Block, unsigned int emsa2BlockLen, byte *output) const
{
	// convert from bit length to byte length
	emsa2BlockLen++;
	if (emsa2BlockLen % 8 > 1)
	{
		if (emsa2Block[0] != 0)
			return 0;
		emsa2Block++;
	}
	emsa2BlockLen /= 8;

	// check last byte
	if (emsa2Block[emsa2BlockLen-1] != 0xcc)
		return 0;

	// skip past the padding until we find the seperator
	unsigned i=1;
	while (i<emsa2BlockLen-1 && emsa2Block[i++] != 0xba)
		if (emsa2Block[i-1] != 0xbb)     // not valid padding
			return 0;
	assert(i==emsa2BlockLen-1 || emsa2Block[i-1]==0xba);

	unsigned int outputLen = emsa2BlockLen - i;
	output[0] = emsa2Block[0];
	memcpy (output+1, emsa2Block+i, outputLen-1);
	return outputLen;
}

// *****************************************************************************

template <word r>
RWFunction<r>::RWFunction(const Integer &n)
	: n(n)
{
}

template <word r>
RWFunction<r>::RWFunction(BufferedTransformation &bt)
{
	BERSequenceDecoder seq(bt);
	n.BERDecode(seq);
	seq.OutputFinished();
}

template <word r>
RWFunction<r>::~RWFunction()
{
}

template <word r>
void RWFunction<r>::DEREncode(BufferedTransformation &bt) const
{
	DERSequenceEncoder seq(bt);
	n.DEREncode(seq);
	seq.InputFinished();
}

template <word r>
Integer RWFunction<r>::ApplyFunction(const Integer &in) const
{
	Integer out = in.Squared()%n;
	const word r2 = r/2;
	const word r3a = (16 + 5 - r) % 16;	// n%16 could be 5 or 13
	const word r3b = (16 + 13 - r) % 16;
	const word r4 = (8 + 5 - r/2) % 8;	// n%8 == 5
	switch (out % 16)
	{
	case r:
		break;
	case r2:
	case r2+8:
		out <<= 1;
		break;
	case r3a:
	case r3b:
		out.Negate();
		out += n;
		break;
	case r4:
	case r4+8:
		out.Negate();
		out += n;
		out <<= 1;
		break;
	default:
		out = Integer::Zero();
	}
	return out;
}

// *****************************************************************************
// private key operations:

template <word r>
InvertibleRWFunction<r>::InvertibleRWFunction(const Integer &n, const Integer &p, const Integer &q, const Integer &u)
	: RWFunction<r>(n), p(p), q(q), u(u)
{
	assert(p*q==n);
	assert(u*q%p==1);
}

// generate a random private key
template <word r>
InvertibleRWFunction<r>::InvertibleRWFunction(RandomNumberGenerator &rng, unsigned int keybits)
{
	assert(keybits >= 16);
	// generate 2 random primes of suitable size
	if (keybits%2==0)
	{
		const Integer minP = Integer(182) << (keybits/2-8);
		const Integer maxP = Integer::Power2(keybits/2)-1;
		p.Randomize(rng, minP, maxP, Integer::PRIME, 3, 8);
		q.Randomize(rng, minP, maxP, Integer::PRIME, 7, 8);
	}
	else
	{
		const Integer minP = Integer::Power2((keybits-1)/2);
		const Integer maxP = Integer(181) << ((keybits+1)/2-8);
		p.Randomize(rng, minP, maxP, Integer::PRIME, 3, 8);
		q.Randomize(rng, minP, maxP, Integer::PRIME, 7, 8);
	}

	n = p * q;
	assert(n.BitCount() == keybits);
	u = EuclideanMultiplicativeInverse(q, p);
	assert(u*q%p==1);
}

template <word r>
InvertibleRWFunction<r>::InvertibleRWFunction(BufferedTransformation &bt)
{
	BERSequenceDecoder seq(bt);
	n.BERDecode(seq);
	p.BERDecode(seq);
	q.BERDecode(seq);
	u.BERDecode(seq);
	seq.OutputFinished();
}

template <word r>
InvertibleRWFunction<r>::~InvertibleRWFunction()
{
}

template <word r>
void InvertibleRWFunction<r>::DEREncode(BufferedTransformation &bt) const
{
	DERSequenceEncoder seq(bt);
	n.DEREncode(seq);
	p.DEREncode(seq);
	q.DEREncode(seq);
	u.DEREncode(seq);
	seq.InputFinished();
}

template <word r>
Integer InvertibleRWFunction<r>::CalculateInverse(const Integer &in) const
{
	Integer cp=in%p, cq=in%q;

	if (Jacobi(cp, p) * Jacobi(cq, q) != 1)
	{
		cp = cp%2 ? (cp+p) >> 1 : cp >> 1;
		cq = cq%2 ? (cq+q) >> 1 : cq >> 1;
	}

	cp = ModularSquareRoot(cp, p);
	cq = ModularSquareRoot(cq, q);

	Integer out = CRT(cq, q, cp, p, u);

	return STDMIN(out, n-out);
}

template class RWFunction<IFSSA_R>;
template class InvertibleRWFunction<IFSSA_R>;

NAMESPACE_END
