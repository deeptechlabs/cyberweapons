#ifndef CRYPTOPP_EC2N_H
#define CRYPTOPP_EC2N_H

#include "gf2n.h"
#include "eprecomp.h"
#include "smartptr.h"

NAMESPACE_BEGIN(CryptoPP)

struct EC2NPoint
{
	EC2NPoint() : identity(true) {}
	EC2NPoint(const PolynomialMod2 &x, const PolynomialMod2 &y)
		: identity(false), x(x), y(y) {}

	bool operator==(const EC2NPoint &t) const
		{return (identity && t.identity) || (!identity && !t.identity && x==t.x && y==t.y);}
	bool operator< (const EC2NPoint &t) const
		{return identity ? !t.identity : (t.identity && (x<t.x || (x<=t.x && y<t.y)));}

	bool identity;
	PolynomialMod2 x, y;
};

class EC2N : public AbstractGroup<EC2NPoint>
{
public:
	typedef GF2N Field;
	typedef Field::Element FieldElement;

	typedef EC2NPoint Point;

	EC2N(const Field &field, const Field::Element &a, const Field::Element &b)
		: field(field), a(a), b(b) {}

	bool Equal(const Point &P, const Point &Q) const;
	const Point& Zero() const {static const Point zero; return zero;}
	const Point& Inverse(const Point &P) const;
	const Point& Add(const Point &P, const Point &Q) const;
	const Point& Double(const Point &P) const;

	Point Multiply(const Integer &k, const Point &P) const
		{return ScalarMultiply(P, k);}
	Point CascadeMultiply(const Integer &k1, const Point &P, const Integer &k2, const Point &Q) const
		{return CascadeScalarMultiply(P, k1, Q, k2);}

	bool ValidateParameters(RandomNumberGenerator &rng) const;
	bool VerifyPoint(const Point &P) const;

	unsigned int EncodedPointSize() const
		{return 1+2*field.MaxElementByteLength();}
	Point DecodePoint(const byte *encodedPoint) const;
	void EncodePoint(byte *encodedPoint, const Point &P) const;

	Integer FieldSize() const {return Integer::Power2(field.MaxElementBitLength());}
	const Field & GetField() const {return field;}
	const FieldElement & GetA() const {return a;}
	const FieldElement & GetB() const {return b;}

private:
	Field field;
	FieldElement a, b;
	mutable Point R;
};

template <class T> class EcPrecomputation;

template<> class EcPrecomputation<EC2N>
{
public:
	EcPrecomputation();
	EcPrecomputation(const EcPrecomputation<EC2N> &ecp);
	EcPrecomputation(const EC2N &ecIn, const EC2N::Point &base, unsigned int maxExpBits, unsigned int storage);
	~EcPrecomputation();

	void Precompute(const EC2N::Point &base, unsigned int maxExpBits, unsigned int storage);
	void Load(BufferedTransformation &storedPrecomputation);
	void Save(BufferedTransformation &storedPrecomputation) const;

	EC2N::Point Multiply(const Integer &exponent) const;
	EC2N::Point CascadeMultiply(const Integer &exponent, const EcPrecomputation<EC2N> &pc2, const Integer &exponent2) const;

private:
	member_ptr<EC2N> ec;
	member_ptr< ExponentiationPrecomputation<EC2N::Point> > ep;
};

NAMESPACE_END

#endif
