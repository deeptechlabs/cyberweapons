#ifndef CRYPTOPP_LUC_H
#define CRYPTOPP_LUC_H

#include "pkcspad.h"
#include "oaep.h"
#include "integer.h"

#include <limits.h>

NAMESPACE_BEGIN(CryptoPP)

class LUCFunction : virtual public TrapdoorFunction
{
public:
	LUCFunction(const Integer &n, const Integer &e) : n(n), e(e) {}
	LUCFunction(BufferedTransformation &bt);
	void DEREncode(BufferedTransformation &bt) const;

	Integer ApplyFunction(const Integer &x) const;
	Integer MaxPreimage() const {return n-1;}
	Integer MaxImage() const {return n-1;}

protected:
	LUCFunction() {}	// to be used only by InvertibleLUCFunction
	Integer n, e;	// these are only modified in constructors
};

class InvertibleLUCFunction : public LUCFunction, public InvertibleTrapdoorFunction
{
public:
	InvertibleLUCFunction(const Integer &n, const Integer &e,
						  const Integer &p, const Integer &q, const Integer &u);
	// generate a random private key
	InvertibleLUCFunction(RandomNumberGenerator &rng, unsigned int keybits, const Integer &eStart=17);
	InvertibleLUCFunction(BufferedTransformation &bt);
	void DEREncode(BufferedTransformation &bt) const;

	Integer CalculateInverse(const Integer &x) const;

protected:
	Integer p, q, u;
};

template <class B>
class LUCPrivateKeyTemplate : public B
{
public:
	LUCPrivateKeyTemplate(const Integer &n, const Integer &e, 
				const Integer &p, const Integer &q, const Integer &u)
		: PublicKeyBaseTemplate<InvertibleLUCFunction>(
			InvertibleLUCFunction(n, e, p, q, u)) {}

	LUCPrivateKeyTemplate(RandomNumberGenerator &rng, unsigned int keybits, const Integer &eStart=17)
		: PublicKeyBaseTemplate<InvertibleLUCFunction>(
			InvertibleLUCFunction(rng, keybits, eStart)) {}

	LUCPrivateKeyTemplate(BufferedTransformation &bt)
		: PublicKeyBaseTemplate<InvertibleLUCFunction>(bt) {}
};

template <class B, class V>
class LUCPublicKeyTemplate : public B
{
public:
	LUCPublicKeyTemplate(const Integer &n, const Integer &e)
		: PublicKeyBaseTemplate<LUCFunction>(LUCFunction(n, e)) {}

	LUCPublicKeyTemplate(const V &priv)
		: PublicKeyBaseTemplate<LUCFunction>(priv.GetTrapdoorFunction()) {}

	LUCPublicKeyTemplate(BufferedTransformation &bt)
		: PublicKeyBaseTemplate<LUCFunction>(bt) {}
};

// analagous to the RSA schemes defined in PKCS #1 v2.0
typedef LUCPrivateKeyTemplate<DecryptorTemplate<OAEP<SHA>, InvertibleLUCFunction> >
	LUCES_OAEP_SHA_Decryptor;
typedef LUCPublicKeyTemplate<EncryptorTemplate<OAEP<SHA>, LUCFunction>, LUCES_OAEP_SHA_Decryptor>
	LUCES_OAEP_SHA_Encryptor;

typedef LUCPrivateKeyTemplate<SignerTemplate<DigestSignerTemplate<PKCS_SignaturePaddingScheme, InvertibleLUCFunction>, PKCS_DecoratedHashModule<SHA> > >
	LUCSSA_PKCS1v15_SHA_Signer;
typedef LUCPublicKeyTemplate<VerifierTemplate<DigestVerifierTemplate<PKCS_SignaturePaddingScheme, LUCFunction>, PKCS_DecoratedHashModule<SHA> >, LUCSSA_PKCS1v15_SHA_Signer>
	LUCSSA_PKCS1v15_SHA_Verifier;

// ********************************************************

class LUCELG_Encryptor : public PK_FixedLengthEncryptor
{
public:
	LUCELG_Encryptor(const Integer &p, const Integer &g, const Integer &y);
	LUCELG_Encryptor(BufferedTransformation &bt);

	void DEREncode(BufferedTransformation &bt) const;

	void Encrypt(RandomNumberGenerator &rng, const byte *plainText, unsigned int plainTextLength, byte *cipherText);

	unsigned int MaxPlainTextLength() const {return STDMIN(255U, modulusLen-3);}
	unsigned int CipherTextLength() const {return 2*modulusLen;}

protected:
	LUCELG_Encryptor() {}
	void RawEncrypt(const Integer &k, const Integer &m, Integer &a, Integer &b) const;
	unsigned int ExponentBitLength() const;

	Integer p, g, y;
	unsigned int modulusLen;
};

class LUCELG_Decryptor : public LUCELG_Encryptor, public PK_FixedLengthDecryptor
{
public:
	LUCELG_Decryptor(const Integer &p, const Integer &g, const Integer &y, const Integer &x);
	LUCELG_Decryptor(RandomNumberGenerator &rng, unsigned int pbits);
	// generate a random private key, given p and g
	LUCELG_Decryptor(RandomNumberGenerator &rng, const Integer &p, const Integer &g);

	LUCELG_Decryptor(BufferedTransformation &bt);
	void DEREncode(BufferedTransformation &bt) const;

	unsigned int Decrypt(const byte *cipherText, byte *plainText);

protected:
	void RawDecrypt(const Integer &a, const Integer &b, Integer &m) const;

	Integer x;
};

// ********************************************************

class LUCELG_DigestVerifier : public DigestVerifier
{
public:
	LUCELG_DigestVerifier(const Integer &p, const Integer &q, const Integer &g, const Integer &y);
	LUCELG_DigestVerifier(BufferedTransformation &bt);

	void DEREncode(BufferedTransformation &bt) const;
	bool VerifyDigest(const byte *digest, unsigned int digestLen, const byte *signature) const;

	unsigned int MaxDigestLength() const {return UINT_MAX;}
	unsigned int DigestSignatureLength() const {return p.ByteCount()+q.ByteCount();}

protected:
	LUCELG_DigestVerifier() {}
	bool RawVerify(const Integer &m, const Integer &a, const Integer &b) const;
	Integer EncodeDigest(const byte *digest, unsigned int digestLen) const;

	Integer p, q, g, y;
};

class LUCELG_DigestSigner : public LUCELG_DigestVerifier, public DigestSigner
{
public:
	LUCELG_DigestSigner(const Integer &p, const Integer &q, const Integer &g, const Integer &y, const Integer &x);
	LUCELG_DigestSigner(RandomNumberGenerator &rng, unsigned int pbits);
	LUCELG_DigestSigner(RandomNumberGenerator &rng, const Integer &p, const Integer &q, const Integer &g);
	LUCELG_DigestSigner(BufferedTransformation &bt);

	void DEREncode(BufferedTransformation &bt) const;
	void SignDigest(RandomNumberGenerator &rng, const byte *digest, unsigned int digestLen, byte *signature) const;

protected:
	void RawSign(RandomNumberGenerator &rng, const Integer &m, Integer &a, Integer &b) const;

	Integer x;
};

template <class H>
class LUCELG_Signer : public SignerTemplate<LUCELG_DigestSigner, H>
{
	typedef SignerTemplate<LUCELG_DigestSigner, H> Base;
public:
	LUCELG_Signer(const Integer &p, const Integer &q, const Integer &g, const Integer &y, const Integer &x)
		: Base(LUCELG_DigestSigner(p, q, g, y, x)) {}

	// generate a random private key
	LUCELG_Signer(RandomNumberGenerator &rng, unsigned int keybits)
		: Base(LUCELG_DigestSigner(rng, keybits)) {}

	// generate a random private key, given p, q, and g
	LUCELG_Signer(RandomNumberGenerator &rng, const Integer &p, const Integer &q, const Integer &g)
		: Base(LUCELG_DigestSigner(rng, p, q, g)) {}

	// load a previously generated key
	LUCELG_Signer(BufferedTransformation &storedKey)
		: Base(storedKey) {}
};

template <class H>
class LUCELG_Verifier : public VerifierTemplate<LUCELG_DigestVerifier, H>
{
	typedef VerifierTemplate<LUCELG_DigestVerifier, H> Base;
public:
	LUCELG_Verifier(const Integer &p, const Integer &q, const Integer &g, const Integer &y)
		: Base(LUCELG_DigestVerifier(p, q, g, y)) {}

	// create a matching public key from a private key
	LUCELG_Verifier(const LUCELG_Signer<H> &priv)
		: Base(priv) {}

	// load a previously generated key
	LUCELG_Verifier(BufferedTransformation &storedKey)
		: Base(storedKey) {}
};

// ********************************************************

class LUCDIF : public PK_SimpleKeyAgreementDomain
{
public:
	LUCDIF(const Integer &p, const Integer &g);
	LUCDIF(RandomNumberGenerator &rng, unsigned int pbits);
	LUCDIF(BufferedTransformation &domainParams);

	void DEREncode(BufferedTransformation &domainParams) const;

	bool ValidateDomainParameters(RandomNumberGenerator &rng) const;
	unsigned int AgreedValueLength() const {return p.ByteCount();}
	unsigned int PrivateKeyLength() const {return p.ByteCount();}
	unsigned int PublicKeyLength() const {return p.ByteCount();}

	void GenerateKeyPair(RandomNumberGenerator &rng, byte *secretKey, byte *publicKey) const;
	bool Agree(byte *agreedValue, const byte *secretKey, const byte *otherPublicKey, bool validateOtherPublicKey=true) const;

	const Integer &Prime() const {return p;}
	const Integer &Generator() const {return g;}

private:
	unsigned int ExponentBitLength() const;

	Integer p, g;
};

NAMESPACE_END

#endif
