// ec2n.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "ec2n.h"
#include "asn.h"
#include "nbtheory.h"	// for primeTable

#include "algebra.cpp"
#include "eprecomp.cpp"

NAMESPACE_BEGIN(CryptoPP)

EC2N::Point EC2N::DecodePoint(const byte *encodedPoint) const
{
	if (encodedPoint[0] != 4)	// TODO: handle compressed points
		return Point();
	else
	{
		unsigned int len = field.MaxElementByteLength();
		return Point(FieldElement(encodedPoint+1, len), FieldElement(encodedPoint+1+len, len));
	}
}

void EC2N::EncodePoint(byte *encodedPoint, const Point &P) const
{
	if (P.identity)
		memset(encodedPoint, 0, EncodedPointSize());
	else
	{
		encodedPoint[0] = 4;	// uncompressed
		unsigned int len = field.MaxElementByteLength();
		P.x.Encode(encodedPoint+1, len);
		P.y.Encode(encodedPoint+1+len, len);
	}
}

bool EC2N::ValidateParameters(RandomNumberGenerator &rng) const
{
	return field.GetModulus().IsIrreducible()
		&& a.CoefficientCount() <= field.MaxElementBitLength()
		&& b.CoefficientCount() <= field.MaxElementBitLength() && !!b;
}

bool EC2N::VerifyPoint(const Point &P) const
{
	const FieldElement &x = P.x, &y = P.y;
	return P.identity || 
		(x.CoefficientCount() <= field.MaxElementBitLength()
		&& y.CoefficientCount() <= field.MaxElementBitLength()
		&& !(((x+a)*x*x+b-(x+y)*y)%field.GetModulus()));
}

bool EC2N::Equal(const Point &P, const Point &Q) const
{
	if (P.identity && Q.identity)
		return true;

	if (P.identity && !Q.identity)
		return false;

	if (!P.identity && Q.identity)
		return false;

	return (field.Equal(P.x,Q.x) && field.Equal(P.y,Q.y));
}

const EC2N::Point& EC2N::Inverse(const Point &P) const
{
	if (P.identity)
		return P;
	else
	{
		R.identity = false;
		R.y = field.Add(P.x, P.y);
		R.x = P.x;
		return R;
	}
}

const EC2N::Point& EC2N::Add(const Point &P, const Point &Q) const
{
	if (P.identity) return Q;
	if (Q.identity) return P;
	if (Equal(P, Q)) return Double(P);
	if (field.Equal(P.x, Q.x) && field.Equal(P.y, field.Add(Q.x, Q.y))) return Zero();

	FieldElement t = field.Add(P.y, Q.y);
	t = field.Divide(t, field.Add(P.x, Q.x));
	FieldElement x = field.Square(t);
	field.Accumulate(x, t);
	field.Accumulate(x, Q.x);
	field.Accumulate(x, a);
	R.y = field.Add(P.y, field.Multiply(t, x));
	field.Accumulate(x, P.x);
	field.Accumulate(R.y, x);

	R.x.swap(x);
	R.identity = false;
	return R;
}

const EC2N::Point& EC2N::Double(const Point &P) const
{
	if (P.identity) return P;
	if (!field.IsUnit(P.x)) return Zero();

	FieldElement t = field.Divide(P.y, P.x);
	field.Accumulate(t, P.x);
	R.y = field.Square(P.x);
	R.x = field.Square(t);
	field.Accumulate(R.x, t);
	field.Accumulate(R.x, a);
	field.Accumulate(R.y, field.Multiply(t, R.x));
	field.Accumulate(R.y, R.x);

	R.identity = false;
	return R;
}

// ********************************************************

EcPrecomputation<EC2N>::EcPrecomputation()
{
}

EcPrecomputation<EC2N>::EcPrecomputation(const EcPrecomputation<EC2N> &ecp)
	: ec(new EC2N(*ecp.ec))
	, ep(new ExponentiationPrecomputation<EC2N::Point>(*ec, *ecp.ep))
{
}

EcPrecomputation<EC2N>::EcPrecomputation(const EC2N &ecIn, const EC2N::Point &base, unsigned int maxExpBits, unsigned int storage)
	: ec(new EC2N(ecIn)), ep(NULL)
{
	Precompute(base, maxExpBits, storage);
}

EcPrecomputation<EC2N>::~EcPrecomputation()
{
}

void EcPrecomputation<EC2N>::Precompute(const EC2N::Point &base, unsigned int maxExpBits, unsigned int storage)
{
	if (!ep.get() || ep->storage < storage)
		ep.reset(new ExponentiationPrecomputation<EC2NPoint>(*ec, base, maxExpBits, storage));
}

void EcPrecomputation<EC2N>::Load(BufferedTransformation &bt)
{
	ep.reset(new ExponentiationPrecomputation<EC2NPoint>(*ec));
	BERSequenceDecoder seq(bt);
	ep->storage = (unsigned int)(Integer(seq).ConvertToLong());
	ep->exponentBase.BERDecode(seq);
	ep->g.resize(ep->storage);

	unsigned int size = ec->GetField().MaxElementByteLength();
	SecByteBlock buffer(size);
	for (unsigned i=0; i<ep->storage; i++)
	{
		ep->g[i].identity = false;
		seq.Get(buffer, size);
		ep->g[i].x.Decode(buffer, size);
		seq.Get(buffer, size);
		ep->g[i].y.Decode(buffer, size);
	}
	seq.OutputFinished();
}

void EcPrecomputation<EC2N>::Save(BufferedTransformation &bt) const
{
	assert(ep.get());
	DERSequenceEncoder seq(bt);
	Integer(ep->storage).DEREncode(seq);
	ep->exponentBase.DEREncode(seq);

	unsigned int size = ec->GetField().MaxElementByteLength();
	SecByteBlock buffer(size);
	for (unsigned i=0; i<ep->storage; i++)
	{
		ep->g[i].x.Encode(buffer, size);
		seq.Put(buffer, size);
		ep->g[i].y.Encode(buffer, size);
		seq.Put(buffer, size);
	}
	seq.InputFinished();
}

EC2N::Point EcPrecomputation<EC2N>::Multiply(const Integer &exponent) const
{
	assert(ep.get());
	return ep->Exponentiate(exponent);
}

EC2N::Point EcPrecomputation<EC2N>::CascadeMultiply(const Integer &exponent, const EcPrecomputation<EC2N> &pc2, const Integer &exponent2) const
{
	assert(ep.get());
	return ep->CascadeExponentiate(exponent, *pc2.ep, exponent2);
}

NAMESPACE_END
