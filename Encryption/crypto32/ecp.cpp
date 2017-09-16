// ecp.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "ecp.h"
#include "asn.h"
#include "nbtheory.h"

#include "algebra.cpp"
#include "eprecomp.cpp"

NAMESPACE_BEGIN(CryptoPP)

ANONYMOUS_NAMESPACE_BEGIN
static inline ECP::Point ToMontgomery(const MontgomeryRepresentation &mr, const ECP::Point &P)
{
	return P.identity ? P : ECP::Point(mr.ConvertIn(P.x), mr.ConvertIn(P.y));
}

static inline ECP::Point FromMontgomery(const MontgomeryRepresentation &mr, const ECP::Point &P)
{
	return P.identity ? P : ECP::Point(mr.ConvertOut(P.x), mr.ConvertOut(P.y));
}
NAMESPACE_END

ECP::Point ECP::DecodePoint(const byte *encodedPoint) const
{
	if (encodedPoint[0] != 4)	// TODO: handle compressed points
		return Point();
	else
	{
		unsigned int len = field.MaxElementByteLength();
		return Point(FieldElement(encodedPoint+1, len), FieldElement(encodedPoint+1+len, len));
	}
}

void ECP::EncodePoint(byte *encodedPoint, const Point &P) const
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

bool ECP::ValidateParameters(RandomNumberGenerator &rng) const
{
	Integer p = FieldSize();
	return p.IsOdd() && VerifyPrime(rng, p)
		&& !a.IsNegative() && a<p && !b.IsNegative() && b<p
		&& ((4*a*a*a+27*b*b)%p).IsPositive();
}

bool ECP::VerifyPoint(const Point &P) const
{
	const FieldElement &x = P.x, &y = P.y;
	Integer p = FieldSize();
	return P.identity ||
		(!x.IsNegative() && x<p && !y.IsNegative() && y<p
		&& !(((x*x+a)*x+b-y*y)%p));
}

bool ECP::Equal(const Point &P, const Point &Q) const
{
	if (P.identity && Q.identity)
		return true;

	if (P.identity && !Q.identity)
		return false;

	if (!P.identity && Q.identity)
		return false;

	return (field.Equal(P.x,Q.x) && field.Equal(P.y,Q.y));
}

const ECP::Point& ECP::Inverse(const Point &P) const
{
	if (P.identity)
		return P;
	else
	{
		R.identity = false;
		R.x = P.x;
		R.y = field.Inverse(P.y);
		return R;
	}
}

const ECP::Point& ECP::Add(const Point &P, const Point &Q) const
{
	if (P.identity) return Q;
	if (Q.identity) return P;
	if (field.Equal(P.x, Q.x))
		return field.Equal(P.y, Q.y) ? Double(P) : Zero();

	FieldElement t = field.Subtract(Q.y, P.y);
	t = field.Divide(t, field.Subtract(Q.x, P.x));
	FieldElement x = field.Subtract(field.Subtract(field.Square(t), P.x), Q.x);
	R.y = field.Subtract(field.Multiply(t, field.Subtract(P.x, x)), P.y);

	R.x.swap(x);
	R.identity = false;
	return R;
}

const ECP::Point& ECP::Double(const Point &P) const
{
	if (P.identity || P.y==field.Zero()) return Zero();

	FieldElement t = field.Square(P.x);
	t = field.Add(field.Add(field.Double(t), t), a);
	t = field.Divide(t, field.Double(P.y));
	FieldElement x = field.Subtract(field.Subtract(field.Square(t), P.x), P.x);
	R.y = field.Subtract(field.Multiply(t, field.Subtract(P.x, x)), P.y);

	R.x.swap(x);
	R.identity = false;
	return R;
}

template <class T, class Iterator> void ParallelInvert(const AbstractRing<T> &ring, Iterator begin, Iterator end)
{
	unsigned int n = end-begin;
	if (n == 1)
		*begin = ring.MultiplicativeInverse(*begin);
	else if (n > 1)
	{
		std::vector<T> vec((n+1)/2);
		unsigned int i;
		Iterator it;

		for (i=0, it=begin; i<n/2; i++, it+=2)
			vec[i] = ring.Multiply(*it, *(it+1));
		if (n%2 == 1)
			vec[n/2] = *it;

		ParallelInvert(ring, vec.begin(), vec.end());

		for (i=0, it=begin; i<n/2; i++, it+=2)
		{
			if (!vec[i])
			{
				*it = ring.MultiplicativeInverse(*it);
				*(it+1) = ring.MultiplicativeInverse(*(it+1));
			}
			else
			{
				std::swap(*it, *(it+1));
				*it = ring.Multiply(*it, vec[i]);
				*(it+1) = ring.Multiply(*(it+1), vec[i]);
			}
		}
		if (n%2 == 1)
			*it = vec[n/2];
	}
}

struct ProjectivePoint
{
	ProjectivePoint() {}
	ProjectivePoint(const Integer &x, const Integer &y, const Integer &z)
		: x(x), y(y), z(z)	{}

	Integer x,y,z;
};

class ProjectiveDoubling
{
public:
	ProjectiveDoubling(const ModularArithmetic &mr, const Integer &a, const Integer &b, const ECPPoint &Q)
		: mr(mr), firstDoubling(true), negated(false)
	{
		if (Q.identity)
		{
			sixteenY4 = P.x = P.y = mr.One();
			aZ4 = P.z = mr.Zero();
		}
		else
		{
			P.x = Q.x;
			P.y = Q.y;
			sixteenY4 = P.z = mr.One();
			aZ4 = a;
		}
	}

	const ProjectivePoint & DoDoublings(unsigned int doublingCount, bool negate)
	{
		for (unsigned int i=0; i<doublingCount; i++)
		{
			twoY = mr.Double(P.y);
			P.z = mr.Multiply(P.z, twoY);
			fourY2 = mr.Square(twoY);
			S = mr.Multiply(fourY2, P.x);
			aZ4 = mr.Multiply(aZ4, sixteenY4);
			M = mr.Square(P.x);
			M = mr.Add(mr.Add(mr.Double(M), M), aZ4);
			P.x = mr.Square(M);
			mr.Reduce(P.x, S);
			mr.Reduce(P.x, S);
			mr.Reduce(S, P.x);
			P.y = mr.Multiply(M, S);
			sixteenY4 = mr.Square(fourY2);
			mr.Reduce(P.y, mr.Half(sixteenY4));
		}

		if (negate != negated)
		{
			negated = !negated;
			P.y = mr.Inverse(P.y);
		}

		return P;
	}

	const ModularArithmetic &mr;
	ProjectivePoint P;
	bool firstDoubling, negated;
	Integer sixteenY4, aZ4, twoY, fourY2, S, M;
};

struct ZIterator
{
	ZIterator() {}
	ZIterator(std::vector<ProjectivePoint>::iterator it) : it(it) {}
	Integer& operator*() {return it->z;}
	int operator-(ZIterator it2) {return it-it2.it;}
	ZIterator operator+(int i) {return ZIterator(it+i);}
	ZIterator& operator+=(int i) {it+=i; return *this;}
	std::vector<ProjectivePoint>::iterator it;
};

ECP::Point ECP::ScalarMultiply(const Point &P, const Integer &k) const
{
	const int windowSize = 5;
	const word windowModulus = 1 << windowSize;

	if (k.BitCount() <= windowSize)
		return AbstractGroup<ECPPoint>::ScalarMultiply(P, k);

	ProjectiveDoubling rd(field, a, b, P);
	std::vector<word> exponents;
	std::vector<ProjectivePoint> bases;
	Integer workExponent = k;
	int futureDoublings = 0, skipCount;

	while (!!workExponent)
	{
		for (skipCount=0; ; skipCount++)
			if (workExponent.GetBit(skipCount))
				break;
		workExponent >>= skipCount;
		
		word subExponent = workExponent % windowModulus;
		workExponent >>= windowSize;
		if (workExponent.IsOdd())
		{
			subExponent = windowModulus - subExponent;
			++workExponent;
			bases.push_back(rd.DoDoublings(futureDoublings+skipCount, true));
		}
		else
			bases.push_back(rd.DoDoublings(futureDoublings+skipCount, false));

		exponents.push_back(subExponent);
		futureDoublings = windowSize;
	}

	std::vector<std::pair<Integer, Point> > finalCascade(bases.size());

	ParallelInvert(field, ZIterator(bases.begin()), ZIterator(bases.end()));

	for (int i=0; i<finalCascade.size(); i++)
	{
		finalCascade[i].first = exponents[i];
		if (!!bases[i].z)
		{
			finalCascade[i].second.identity = false;
			finalCascade[i].second.x = field.Square(bases[i].z);
			finalCascade[i].second.y = field.Multiply(finalCascade[i].second.x, bases[i].z);
			finalCascade[i].second.x = field.Multiply(finalCascade[i].second.x, bases[i].x);
			finalCascade[i].second.y = field.Multiply(finalCascade[i].second.y, bases[i].y);
		}
	}

	return GeneralCascadeMultiplication(*this, finalCascade.begin(), finalCascade.end());
}

ECP::Point ECP::Multiply(const Integer &k, const Point &P) const
{
//	return ScalarMultiply(P, k);
	MontgomeryRepresentation mr(field.GetModulus());
	ECP ecpmr(mr, mr.ConvertIn(a), mr.ConvertIn(b));
	return FromMontgomery(mr, ecpmr.ScalarMultiply(ToMontgomery(mr, P), k));
}

ECP::Point ECP::CascadeMultiply(const Integer &k1, const Point &P, const Integer &k2, const Point &Q) const
{
//	return CascadeMultiplication(*this, P, k1, Q, k2);
	MontgomeryRepresentation mr(field.GetModulus());
	ECP ecpmr(mr, mr.ConvertIn(a), mr.ConvertIn(b));
	return FromMontgomery(mr, ecpmr.CascadeScalarMultiply(ToMontgomery(mr, P), k1, ToMontgomery(mr, Q), k2));
}

// ********************************************************

EcPrecomputation<ECP>::EcPrecomputation()
{
}

EcPrecomputation<ECP>::EcPrecomputation(const EcPrecomputation<ECP> &ecp)
	: mr(new MontgomeryRepresentation(*ecp.mr))
	, ec(new ECP(*mr, ecp.ec->GetA(), ecp.ec->GetB()))
	, ep(new ExponentiationPrecomputation<ECP::Point>(*ec, *ecp.ep))
{
}

EcPrecomputation<ECP>::EcPrecomputation(const ECP &ecIn, const ECP::Point &base, unsigned int maxExpBits, unsigned int storage)
	: mr(new MontgomeryRepresentation(ecIn.GetField().GetModulus()))
	, ec(new ECP(*mr, mr->ConvertIn(ecIn.GetA()), mr->ConvertIn(ecIn.GetB())))
	, ep(NULL)
{
	Precompute(base, maxExpBits, storage);
}

EcPrecomputation<ECP>::~EcPrecomputation()
{
}

void EcPrecomputation<ECP>::Precompute(const ECP::Point &base, unsigned int maxExpBits, unsigned int storage)
{
	ep.reset(new ExponentiationPrecomputation<ECP::Point>(*ec, ToMontgomery(*mr, base), maxExpBits, storage));
}

void EcPrecomputation<ECP>::Load(BufferedTransformation &bt)
{
	ep.reset(new ExponentiationPrecomputation<ECP::Point>(*ec));
	BERSequenceDecoder seq(bt);
	ep->storage = (unsigned int)(Integer(seq).ConvertToLong());
	ep->exponentBase.BERDecode(seq);
	ep->g.resize(ep->storage);

	for (unsigned i=0; i<ep->storage; i++)
	{
		ep->g[i].identity = false;
		ep->g[i].x.BERDecode(seq);
		ep->g[i].y.BERDecode(seq);
	}
	seq.OutputFinished();
}

void EcPrecomputation<ECP>::Save(BufferedTransformation &bt) const
{
	assert(ep.get());
	DERSequenceEncoder seq(bt);
	Integer(ep->storage).DEREncode(seq);
	ep->exponentBase.DEREncode(seq);

	for (unsigned i=0; i<ep->storage; i++)
	{
		ep->g[i].x.DEREncode(seq);
		ep->g[i].y.DEREncode(seq);
	}
	seq.InputFinished();
}

ECP::Point EcPrecomputation<ECP>::Multiply(const Integer &exponent) const
{
	assert(ep.get());
	return FromMontgomery(*mr, ep->Exponentiate(exponent));
}

ECP::Point EcPrecomputation<ECP>::CascadeMultiply(const Integer &exponent, const EcPrecomputation<ECP> &pc2, const Integer &exponent2) const
{
	assert(ep.get());
	return FromMontgomery(*mr, ep->CascadeExponentiate(exponent, *pc2.ep, exponent2));
}

NAMESPACE_END
