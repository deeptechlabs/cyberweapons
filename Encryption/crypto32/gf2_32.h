#ifndef CRYPTOPP_GF2_32_H
#define CRYPTOPP_GF2_32_H

#include "cryptlib.h"

NAMESPACE_BEGIN(CryptoPP)

class GF2_32
{
public:
	typedef word32 Element;
	typedef int RandomizationParameter;

	GF2_32(word32 modulus) : m_modulus(modulus) {}

	Element RandomElement(RandomNumberGenerator &rng, int ignored = 0) const
		{return rng.GetLong();}

	bool Equal(Element a, Element b) const
		{return a==b;}

	Element Zero() const
		{return 0;}

	Element Add(Element a, Element b) const
		{return a^b;}

	Element& Accumulate(Element &a, Element b) const
		{return a^=b;}

	Element Inverse(Element a) const
		{return a;}

	Element Subtract(Element a, Element b) const
		{return a^b;}

	Element& Reduce(Element &a, Element b) const
		{return a^=b;}

	Element Double(Element a) const
		{return 0;}

	Element One() const
		{return 1;}

	Element Multiply(Element a, Element b) const;

	Element Square(Element a) const
		{return Multiply(a, a);}

	bool IsUnit(Element a) const
		{return a != 0;}

	Element MultiplicativeInverse(Element a) const;

	Element Divide(Element a, Element b) const
		{return Multiply(a, MultiplicativeInverse(b));}

private:
	word32 m_modulus;
};

NAMESPACE_END

#endif
