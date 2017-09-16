#ifndef CRYPTOPP_MODARITH_H
#define CRYPTOPP_MODARITH_H

// implementations are in integer.cpp

#include "cryptlib.h"
#include "misc.h"
#include "integer.h"
#include "algebra.h"

NAMESPACE_BEGIN(CryptoPP)

class ModularArithmetic : public RingWithDefaultMultiplicativeGroup<Integer>
{
public:

	typedef int RandomizationParameter;
	typedef Integer Element ;

	ModularArithmetic(const Integer &modulus = Integer::One())
		: modulus(modulus), result((word)0, modulus.reg.size) {}

	ModularArithmetic(const ModularArithmetic &ma)
		: modulus(ma.modulus), result((word)0, modulus.reg.size) {}

	const Integer& GetModulus() const {return modulus;}
	void SetModulus(const Integer &newModulus) {modulus = newModulus; result.reg.Resize(modulus.reg.size);}

	virtual Integer ConvertIn(const Integer &a) const
		{return a%modulus;}

	virtual Integer ConvertOut(const Integer &a) const
		{return a;}

	const Integer& Half(const Integer &a) const;

	bool Equal(const Integer &a, const Integer &b) const
		{return a==b;}

	const Integer& Zero() const
		{return Integer::Zero();}

	const Integer& Add(const Integer &a, const Integer &b) const;

	Integer& Accumulate(Integer &a, const Integer &b) const;

	const Integer& Inverse(const Integer &a) const;

	const Integer& Subtract(const Integer &a, const Integer &b) const;

	Integer& Reduce(Integer &a, const Integer &b) const;

	const Integer& Double(const Integer &a) const
		{return Add(a, a);}

	const Integer& One() const
		{return Integer::One();}

	const Integer& Multiply(const Integer &a, const Integer &b) const
		{return result1 = a*b%modulus;}

	const Integer& Square(const Integer &a) const
		{return result1 = a.Squared()%modulus;}

	virtual bool IsUnit(const Integer &a) const
		{return Integer::Gcd(a, modulus).IsUnit();}

	const Integer& MultiplicativeInverse(const Integer &a) const;

	const Integer& Divide(const Integer &a, const Integer &b) const
		{return Multiply(a, MultiplicativeInverse(b));}

	virtual Integer Exponentiate(const Integer &a, const Integer &e) const;

	virtual Integer CascadeExponentiate(const Integer &x, const Integer &e1, const Integer &y, const Integer &e2) const;

	unsigned int MaxElementBitLength() const
		{return (modulus-1).BitCount();}

	unsigned int MaxElementByteLength() const
		{return (modulus-1).ByteCount();}

	Element RandomElement( RandomNumberGenerator &rng , const RandomizationParameter &ignore_for_now = 0 ) const
		// left RandomizationParameter arg as ref in case RandomizationParameter becomes a more complicated struct
	{ 
		return Element( rng , Integer( (long) 0) , modulus - Integer( (long) 1 )   ) ; 
	}   

	static const RandomizationParameter DefaultRandomizationParameter ;

protected:
	Integer modulus;
	mutable Integer result, result1;

};

// const ModularArithmetic::RandomizationParameter ModularArithmetic::DefaultRandomizationParameter = 0 ;

// do modular arithmetics in Montgomery representation for increased speed
class MontgomeryRepresentation : public ModularArithmetic
{
public:
	MontgomeryRepresentation(const Integer &modulus);	// modulus must be odd

	Integer ConvertIn(const Integer &a) const
		{return (a<<(WORD_BITS*modulus.reg.size))%modulus;}

	Integer ConvertOut(const Integer &a) const;

	const Integer& One() const
		{return result1 = Integer::Power2(WORD_BITS*modulus.reg.size)%modulus;}

	const Integer& Multiply(const Integer &a, const Integer &b) const;

	const Integer& Square(const Integer &a) const;

	const Integer& MultiplicativeInverse(const Integer &a) const;

	Integer Exponentiate(const Integer &a, const Integer &e) const
		{return AbstractRing<Integer>::Exponentiate(a, e);}

	Integer CascadeExponentiate(const Integer &x, const Integer &e1, const Integer &y, const Integer &e2) const
		{return AbstractRing<Integer>::CascadeExponentiate(x, e1, y, e2);}

private:
	Integer u;
	SecWordBlock workspace;
};

NAMESPACE_END

#endif
