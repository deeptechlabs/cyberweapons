// luc.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "luc.h"
#include "asn.h"
#include "nbtheory.h"
#include "sha.h"

#include "pubkey.cpp"
#include "oaep.cpp"

NAMESPACE_BEGIN(CryptoPP)

INSTANTIATE_PUBKEY_TEMPLATES_MACRO(OAEP<SHA>, PKCS_SignaturePaddingScheme, LUCFunction, InvertibleLUCFunction);

LUCFunction::LUCFunction(BufferedTransformation &bt)
{
	BERSequenceDecoder seq(bt);
	n.BERDecode(seq);
	e.BERDecode(seq);
	seq.OutputFinished();
}

void LUCFunction::DEREncode(BufferedTransformation &bt) const
{
	DERSequenceEncoder seq(bt);
	n.DEREncode(seq);
	e.DEREncode(seq);
	seq.InputFinished();
}

Integer LUCFunction::ApplyFunction(const Integer &x) const
{
	return Lucas(e, x, n);
}

// *****************************************************************************
// private key operations:

InvertibleLUCFunction::InvertibleLUCFunction(const Integer &nIn, const Integer &eIn,
							 const Integer &pIn, const Integer &qIn, const Integer &uIn)
	: LUCFunction(nIn, eIn), p(pIn), q(qIn), u(uIn)
{
	assert(p*q==n);
	assert(u*q%p==1);
}

// generate a random private key
InvertibleLUCFunction::InvertibleLUCFunction(RandomNumberGenerator &rng, unsigned int keybits, const Integer &eStart)
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
	const Integer lcm = LCM(LCM(p-1, q-1), LCM(p+1, q+1));
	// make sure e starts odd
	for (e = eStart+(1-eStart%2); GCD(e, lcm)!=1; ++e, ++e);
	u = EuclideanMultiplicativeInverse(q, p);
	n = p * q;
	assert(n.BitCount() == keybits);
}

InvertibleLUCFunction::InvertibleLUCFunction(BufferedTransformation &bt)
{
	BERSequenceDecoder seq(bt);

	Integer version(seq);
	if (!!version)  // make sure version is 0
		BERDecodeError();

	n.BERDecode(seq);
	e.BERDecode(seq);
	p.BERDecode(seq);
	q.BERDecode(seq);
	u.BERDecode(seq);
	seq.OutputFinished();
}

void InvertibleLUCFunction::DEREncode(BufferedTransformation &bt) const
{
	DERSequenceEncoder seq(bt);

	const byte version[] = {INTEGER, 1, 0};
	seq.Put(version, sizeof(version));
	n.DEREncode(seq);
	e.DEREncode(seq);
	p.DEREncode(seq);
	q.DEREncode(seq);
	u.DEREncode(seq);
	seq.InputFinished();
}

Integer InvertibleLUCFunction::CalculateInverse(const Integer &x) const
{
	 return InverseLucas(e, x, q, p, u);
}

// ********************************************************

LUCELG_Encryptor::LUCELG_Encryptor(const Integer &p, const Integer &g, const Integer &y)
	: p(p), g(g), y(y), modulusLen(p.ByteCount())
{
}

LUCELG_Encryptor::LUCELG_Encryptor(BufferedTransformation &bt)
{
	BERSequenceDecoder seq(bt);
	p.BERDecode(seq);
	g.BERDecode(seq);
	y.BERDecode(seq);
	seq.OutputFinished();
	modulusLen=p.ByteCount();
}

void LUCELG_Encryptor::DEREncode(BufferedTransformation &bt) const
{
	DERSequenceEncoder seq(bt);
	p.DEREncode(seq);
	g.DEREncode(seq);
	y.DEREncode(seq);
	seq.InputFinished();
}

void LUCELG_Encryptor::Encrypt(RandomNumberGenerator &rng, const byte *plainText, unsigned int plainTextLength, byte *cipherText)
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

void LUCELG_Encryptor::RawEncrypt(const Integer &k, const Integer &m, Integer &a, Integer &b) const
{
	a = Lucas(k, g, p);
	b = m * Lucas(k, y, p) % p;
}

unsigned int LUCELG_Encryptor::ExponentBitLength() const
{
	// use 2*p.BitCount() because we're in GF(p^2)
	return 2*DiscreteLogWorkFactor(2*p.BitCount());
}

// *************************************************************

LUCELG_Decryptor::LUCELG_Decryptor(const Integer &p, const Integer &g, const Integer &y, const Integer &x)
	: LUCELG_Encryptor(p, g, y), x(x)
{
}

LUCELG_Decryptor::LUCELG_Decryptor(RandomNumberGenerator &rng, unsigned int pbits)
{
	PrimeAndGenerator pg(-1, rng, pbits);
	p = pg.Prime();
	modulusLen=p.ByteCount();
	g = pg.Generator();
	x.Randomize(rng, ExponentBitLength());
	y = Lucas(x, g, p);
}

LUCELG_Decryptor::LUCELG_Decryptor(RandomNumberGenerator &rng, const Integer &pIn, const Integer &gIn)
{
	p = pIn;
	modulusLen=p.ByteCount();
	g = gIn;
	x.Randomize(rng, ExponentBitLength());
	y = Lucas(x, g, p);
}

LUCELG_Decryptor::LUCELG_Decryptor(BufferedTransformation &bt)
{
	BERSequenceDecoder seq(bt);
	p.BERDecode(seq);
	g.BERDecode(seq);
	y.BERDecode(seq);
	x.BERDecode(seq);
	seq.OutputFinished();
	modulusLen=p.ByteCount();
}

void LUCELG_Decryptor::DEREncode(BufferedTransformation &bt) const
{
	DERSequenceEncoder seq(bt);
	p.DEREncode(seq);
	g.DEREncode(seq);
	y.DEREncode(seq);
	x.DEREncode(seq);
	seq.InputFinished();
}

unsigned int LUCELG_Decryptor::Decrypt(const byte *cipherText, byte *plainText)
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

void LUCELG_Decryptor::RawDecrypt(const Integer &a, const Integer &b, Integer &m) const
{
	m = b * EuclideanMultiplicativeInverse(Lucas(x, a, p), p) % p;
}

// ******************************************************************

LUCELG_DigestVerifier::LUCELG_DigestVerifier(const Integer &p, const Integer &q, const Integer &g, const Integer &y)
	: p(p), q(q), g(g), y(y)
{
}

LUCELG_DigestVerifier::LUCELG_DigestVerifier(BufferedTransformation &bt)
{
	BERSequenceDecoder seq(bt);
	p.BERDecode(seq);
	q.BERDecode(seq);
	g.BERDecode(seq);
	y.BERDecode(seq);
	seq.OutputFinished();
}

Integer LUCELG_DigestVerifier::EncodeDigest(const byte *digest, unsigned int digestLen) const
{
	Integer h;
	if (digestLen*8 <= q.BitCount())
		h.Decode(digest, digestLen);
	else
	{
		h.Decode(digest, q.ByteCount());
		h >>= q.ByteCount()*8 - q.BitCount();
	}
	return h;
}

void LUCELG_DigestVerifier::DEREncode(BufferedTransformation &bt) const
{
	DERSequenceEncoder seq(bt);
	p.DEREncode(seq);
	q.DEREncode(seq);
	g.DEREncode(seq);
	y.DEREncode(seq);
	seq.InputFinished();
}

bool LUCELG_DigestVerifier::VerifyDigest(const byte *digest, unsigned int digestLen, const byte *signature) const
{
	Integer m = EncodeDigest(digest, digestLen);
	Integer r(signature, p.ByteCount());
	Integer s(signature+p.ByteCount(), q.ByteCount());
	return RawVerify(m, r, s);
}

bool LUCELG_DigestVerifier::RawVerify(const Integer &m, const Integer &r, const Integer &s) const
{
	Integer Vsg=Lucas(s, g, p);
	Integer Vry=Lucas((r+m)%q, y, p);
	return (Vsg*Vsg + Vry*Vry + r*r) % p == (Vsg * Vry * r + 4) % p;
}

// *************************************************************

LUCELG_DigestSigner::LUCELG_DigestSigner(const Integer &p, const Integer &q, const Integer &g, const Integer &y, const Integer &x)
	: LUCELG_DigestVerifier(p, q, g, y), x(x)
{
}

LUCELG_DigestSigner::LUCELG_DigestSigner(RandomNumberGenerator &rng, unsigned int pbits)
{
	PrimeAndGenerator pg(-1, rng, pbits, 2*DiscreteLogWorkFactor(2*pbits));
	p = pg.Prime();
	q = pg.SubPrime();
	g = pg.Generator();
	x.Randomize(rng, 2, q-2, Integer::ANY);
	y = Lucas(x, g, p);
}

LUCELG_DigestSigner::LUCELG_DigestSigner(RandomNumberGenerator &rng, const Integer &pIn, const Integer &qIn, const Integer &gIn)
{
	p = pIn;
	q = qIn;
	g = gIn;
	x.Randomize(rng, 2, q-2, Integer::ANY);
	y = Lucas(x, g, p);
}

LUCELG_DigestSigner::LUCELG_DigestSigner(BufferedTransformation &bt)
{
	BERSequenceDecoder seq(bt);
	p.BERDecode(seq);
	q.BERDecode(seq);
	g.BERDecode(seq);
	y.BERDecode(seq);
	x.BERDecode(seq);
	seq.OutputFinished();
}

void LUCELG_DigestSigner::DEREncode(BufferedTransformation &bt) const
{
	DERSequenceEncoder seq(bt);
	p.DEREncode(seq);
	q.DEREncode(seq);
	g.DEREncode(seq);
	y.DEREncode(seq);
	x.DEREncode(seq);
	seq.InputFinished();
}

void LUCELG_DigestSigner::SignDigest(RandomNumberGenerator &rng, const byte *digest, unsigned int digestLen, byte *signature) const
{
	Integer m = EncodeDigest(digest, digestLen);
	Integer r;
	Integer s;

	RawSign(rng, m, r, s);
	r.Encode(signature, p.ByteCount());
	s.Encode(signature+p.ByteCount(), q.ByteCount());
}

void LUCELG_DigestSigner::RawSign(RandomNumberGenerator &rng, const Integer &m, Integer &r, Integer &s) const
{
	Integer k(rng, 2, q-2, Integer::ANY);
	r = Lucas(k, g, p);
	s = (k + x*(r+m)) % q;
}

// ********************************************************

LUCDIF::LUCDIF(const Integer &p, const Integer &g)
	: p(p), g(g)
{
}

LUCDIF::LUCDIF(RandomNumberGenerator &rng, unsigned int pbits)
{
	PrimeAndGenerator pg(-1, rng, pbits);
	p = pg.Prime();
	g = pg.Generator();
}

LUCDIF::LUCDIF(BufferedTransformation &bt)
{
	BERSequenceDecoder seq(bt);
	p.BERDecode(seq);
	g.BERDecode(seq);
	seq.OutputFinished();
}

void LUCDIF::DEREncode(BufferedTransformation &bt) const
{
	DERSequenceEncoder seq(bt);
	p.DEREncode(seq);
	g.DEREncode(seq);
	seq.InputFinished();
}

bool LUCDIF::ValidateDomainParameters(RandomNumberGenerator &rng) const
{
	return VerifyPrime(rng, p) && VerifyPrime(rng, (p+1)/2) && g > 1 && g < p && Jacobi(g*g-4, p)==-1 && Lucas((p+1)/2, g, p)==2;
}

void LUCDIF::GenerateKeyPair(RandomNumberGenerator &rng, byte *privateKey, byte *publicKey) const
{
	Integer x(rng, ExponentBitLength());
	Integer y = Lucas(x, g, p);
	x.Encode(privateKey, PrivateKeyLength());
	y.Encode(publicKey, PublicKeyLength());
}

bool LUCDIF::Agree(byte *agreedValue, const byte *privateKey, const byte *otherPublicKey, bool validateOtherPublicKey) const
{
	Integer w(otherPublicKey, PublicKeyLength());
	// verifying that Lucas((p+1)/2, w, p)==2 is omitted because it's too costly
	// and at most 1 bit is leaked if it's false
	if (validateOtherPublicKey && !(w > 1 && w < p && Jacobi(w*w-4, p)==-1))
		return false;

	Integer s(privateKey, PrivateKeyLength());
	Integer z = Lucas(s, w, p);
	z.Encode(agreedValue, AgreedValueLength());
	return true;
}

unsigned int LUCDIF::ExponentBitLength() const
{
	return 2*DiscreteLogWorkFactor(2*p.BitCount());
}

NAMESPACE_END
