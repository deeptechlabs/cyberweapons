// elgamal.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "elgamal.h"
#include "asn.h"
#include "nbtheory.h"

NAMESPACE_BEGIN(CryptoPP)

ElGamalEncryptor::ElGamalEncryptor(const Integer &p, const Integer &g, const Integer &y)
	: p(p), g(g), y(y), modulusLen(p.ByteCount()),
	  gpc(p, g, ExponentBitLength(), 1), ypc(p, y, ExponentBitLength(), 1)
{
}

ElGamalEncryptor::ElGamalEncryptor(BufferedTransformation &bt)
{
	BERSequenceDecoder seq(bt);
	p.BERDecode(seq);
	g.BERDecode(seq);
	y.BERDecode(seq);
	seq.OutputFinished();

	modulusLen=p.ByteCount();
	gpc.Precompute(p, g, ExponentBitLength(), 1);
	ypc.Precompute(p, y, ExponentBitLength(), 1);
}

void ElGamalEncryptor::DEREncode(BufferedTransformation &bt) const
{
	DERSequenceEncoder seq(bt);
	p.DEREncode(seq);
	g.DEREncode(seq);
	y.DEREncode(seq);
	seq.InputFinished();
}

void ElGamalEncryptor::Precompute(unsigned int precomputationStorage)
{
	gpc.Precompute(p, g, ExponentBitLength(), precomputationStorage);
	ypc.Precompute(p, y, ExponentBitLength(), precomputationStorage);
}

void ElGamalEncryptor::LoadPrecomputation(BufferedTransformation &bt)
{
	gpc.Load(p, bt);
	ypc.Load(p, bt);
}

void ElGamalEncryptor::SavePrecomputation(BufferedTransformation &bt) const
{
	gpc.Save(bt);
	ypc.Save(bt);
}

void ElGamalEncryptor::Encrypt(RandomNumberGenerator &rng, const byte *plainText, unsigned int plainTextLength, byte *cipherText)
{
	assert(plainTextLength <= MaxPlainTextLength());

	SecByteBlock block(modulusLen-1);
	rng.GetBlock(block, modulusLen-2-plainTextLength);
	memcpy(block+modulusLen-2-plainTextLength, plainText, plainTextLength);
	block[modulusLen-2] = plainTextLength;

	Integer m(block, modulusLen-1);
	Integer a,b;
	RawEncrypt(Integer(rng, ExponentBitLength()), m, a, b);

	a.Encode(cipherText, modulusLen);
	b.Encode(cipherText+modulusLen, modulusLen);
}

void ElGamalEncryptor::RawEncrypt(const Integer &k, const Integer &m, Integer &a, Integer &b) const
{
	a = gpc.Exponentiate(k);
	b = m * ypc.Exponentiate(k) % p;
}

unsigned int ElGamalEncryptor::ExponentBitLength() const
{
	return 2*DiscreteLogWorkFactor(p.BitCount());
}

// *************************************************************

ElGamalDecryptor::ElGamalDecryptor(const Integer &p, const Integer &g, const Integer &y, const Integer &x)
	: ElGamalEncryptor(p, g, y), x(x)
{
}

ElGamalDecryptor::ElGamalDecryptor(RandomNumberGenerator &rng, unsigned int pbits)
{
	PrimeAndGenerator pg(1, rng, pbits);
	p = pg.Prime();
	modulusLen=p.ByteCount();
	g = pg.Generator();
	x.Randomize(rng, ExponentBitLength());
	gpc.Precompute(p, g, ExponentBitLength(), 1);
	y = gpc.Exponentiate(x);
	ypc.Precompute(p, y, ExponentBitLength(), 1);
}

ElGamalDecryptor::ElGamalDecryptor(RandomNumberGenerator &rng, const Integer &pIn, const Integer &gIn)
{
	p = pIn;
	modulusLen=p.ByteCount();
	g = gIn;
	x.Randomize(rng, ExponentBitLength());
	gpc.Precompute(p, g, ExponentBitLength(), 1);
	y = gpc.Exponentiate(x);
	ypc.Precompute(p, y, ExponentBitLength(), 1);
}

ElGamalDecryptor::ElGamalDecryptor(BufferedTransformation &bt)
{
	BERSequenceDecoder seq(bt);
	p.BERDecode(seq);
	g.BERDecode(seq);
	y.BERDecode(seq);
	x.BERDecode(seq);
	seq.OutputFinished();

	modulusLen=p.ByteCount();
	gpc.Precompute(p, g, ExponentBitLength(), 1);
	ypc.Precompute(p, y, ExponentBitLength(), 1);
}

void ElGamalDecryptor::DEREncode(BufferedTransformation &bt) const
{
	DERSequenceEncoder seq(bt);
	p.DEREncode(seq);
	g.DEREncode(seq);
	y.DEREncode(seq);
	x.DEREncode(seq);
	seq.InputFinished();
}

unsigned int ElGamalDecryptor::Decrypt(const byte *cipherText, byte *plainText)
{
	Integer a(cipherText, modulusLen);
	Integer b(cipherText+modulusLen, modulusLen);
	Integer m;

	RawDecrypt(a, b, m);
	m.Encode(plainText, 1);
	unsigned int plainTextLength = plainText[0];
	if (plainTextLength > MaxPlainTextLength())
		return 0;
	m >>= 8;
	m.Encode(plainText, plainTextLength);
	return plainTextLength;
}

void ElGamalDecryptor::RawDecrypt(const Integer &a, const Integer &b, Integer &m) const
{
	if (x.BitCount()+20 < p.BitCount()) // if x is short
		m = b * EuclideanMultiplicativeInverse(a_exp_b_mod_c(a, x, p), p) % p;
	else	// save a multiplicative inverse calculation
		m = b * a_exp_b_mod_c(a, p-1-x, p) % p;
}

NAMESPACE_END
