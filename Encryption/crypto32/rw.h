#ifndef CRYPTOPP_RW_H
#define CRYPTOPP_RW_H

#include "pubkey.h"
#include "integer.h"

NAMESPACE_BEGIN(CryptoPP)

const word IFSSR_R = 6;
const word IFSSA_R = 12;

class EMSA2Pad
{
public:
	unsigned int MaxUnpaddedLength(unsigned int paddedLength) const {return (paddedLength+1)/8-2;}

	void Pad(RandomNumberGenerator &rng, const byte *raw, unsigned int inputLength, byte *padded, unsigned int paddedLength) const;
	unsigned int Unpad(const byte *padded, unsigned int paddedLength, byte *raw) const;
};

template <class H>
class EMSA2DecoratedHashModule : public HashModule
{
public:
	EMSA2DecoratedHashModule() : empty(true) {}
	void Update(const byte *input, unsigned int length)
		{h.Update(input, length); empty = empty && length==0;}
	unsigned int DigestSize() const;
	void Final(byte *digest);

private:
	H h;
	bool empty;
};

template <class H> struct EMSA2DigestDecoration
{
	static const byte decoration;
};

// EMSA2DecoratedHashModule can be instantiated with the following two classes.
class SHA;
class RIPEMD160;

template <class H>
void EMSA2DecoratedHashModule<H>::Final(byte *digest)
{
	digest[0] = empty ? 0x4b : 0x6b;
	h.Final(digest+1);
	digest[DigestSize()-1] = EMSA2DigestDecoration<H>::decoration;
}

template <class H>
unsigned int EMSA2DecoratedHashModule<H>::DigestSize() const
{
	return h.DigestSize() + 2;
}

// *****************************************************************************

template <word r>
class RWFunction : virtual public TrapdoorFunction
{
public:
	RWFunction(const Integer &n);
	RWFunction(BufferedTransformation &bt);
	void DEREncode(BufferedTransformation &bt) const;
	~RWFunction();

	Integer ApplyFunction(const Integer &x) const;
	Integer MaxPreimage() const {return n-1;}
	Integer MaxImage() const {return n>>1;}

	const Integer& GetModulus() const {return n;}

protected:
	RWFunction() {}	// to be used only by InvertibleRWFunction
	Integer n;
};

template <word r>
class InvertibleRWFunction : public RWFunction<r>, public InvertibleTrapdoorFunction
{
public:
	InvertibleRWFunction(const Integer &n, const Integer &p, const Integer &q, const Integer &u);
	// generate a random private key
	InvertibleRWFunction(RandomNumberGenerator &rng, unsigned int keybits);
	InvertibleRWFunction(BufferedTransformation &bt);
	~InvertibleRWFunction();
	void DEREncode(BufferedTransformation &bt) const;

	Integer CalculateInverse(const Integer &x) const;

	const Integer& GetPrime1() const {return p;}
	const Integer& GetPrime2() const {return q;}

protected:
	Integer p, q, u;
};

template <class H>
class RWSigner : public SignerTemplate<DigestSignerTemplate<EMSA2Pad, InvertibleRWFunction<IFSSA_R> >, EMSA2DecoratedHashModule<H> >
{
public:
	RWSigner(const Integer &n, const Integer &p, const Integer &q, const Integer &u)
		: PublicKeyBaseTemplate<InvertibleRWFunction<IFSSA_R> >(
			InvertibleRWFunction<IFSSA_R>(n, p, q, u)) {}

	RWSigner(RandomNumberGenerator &rng, unsigned int keybits)
		: PublicKeyBaseTemplate<InvertibleRWFunction<IFSSA_R> >(
			InvertibleRWFunction<IFSSA_R>(rng, keybits)) {}

	RWSigner(BufferedTransformation &bt)
		: PublicKeyBaseTemplate<InvertibleRWFunction<IFSSA_R> >(bt) {}
};

template <class H>
class RWVerifier : public VerifierTemplate<DigestVerifierTemplate<EMSA2Pad, RWFunction<IFSSA_R> >, EMSA2DecoratedHashModule<H> >
{
public:
	RWVerifier(const Integer &n)
		: PublicKeyBaseTemplate<RWFunction<IFSSA_R> >(RWFunction<IFSSA_R>(n)) {}

	RWVerifier(const RWSigner<H> &priv)
		: PublicKeyBaseTemplate<RWFunction<IFSSA_R> >(priv.GetTrapdoorFunction()) {}

	RWVerifier(BufferedTransformation &bt)
		: PublicKeyBaseTemplate<RWFunction<IFSSA_R> >(bt) {}
};

NAMESPACE_END

#endif
