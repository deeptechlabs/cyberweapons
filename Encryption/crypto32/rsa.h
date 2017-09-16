#ifndef CRYPTOPP_RSA_H
#define CRYPTOPP_RSA_H

#include "pkcspad.h"
#include "oaep.h"
#include "integer.h"

NAMESPACE_BEGIN(CryptoPP)

class RSAFunction : virtual public TrapdoorFunction
{
public:
	RSAFunction(const Integer &n, const Integer &e) : n(n), e(e) {}
	RSAFunction(BufferedTransformation &bt);
	void DEREncode(BufferedTransformation &bt) const;

	Integer ApplyFunction(const Integer &x) const;
	Integer MaxPreimage() const {return n-1;}
	Integer MaxImage() const {return n-1;}

	const Integer& GetModulus() const {return n;}
	const Integer& GetExponent() const {return e;}

protected:
	RSAFunction() {}	// to be used only by InvertibleRSAFunction
	Integer n, e;	// these are only modified in constructors
};

class InvertibleRSAFunction : public RSAFunction, public InvertibleTrapdoorFunction
{
public:
	InvertibleRSAFunction(const Integer &n, const Integer &e, const Integer &d,
						  const Integer &p, const Integer &q, const Integer &dp, const Integer &dq, const Integer &u);
	// generate a random private key
	InvertibleRSAFunction(RandomNumberGenerator &rng, unsigned int keybits, const Integer &eStart=17);
	InvertibleRSAFunction(BufferedTransformation &bt);
	void DEREncode(BufferedTransformation &bt) const;

	Integer CalculateInverse(const Integer &x) const;

	const Integer& GetPrime1() const {return p;}
	const Integer& GetPrime2() const {return q;}
	const Integer& GetDecryptionExponent() const {return d;}

protected:
	Integer d, p, q, dp, dq, u;
};

template <class B>
class RSAPrivateKeyTemplate : public B
{
public:
	RSAPrivateKeyTemplate(const Integer &n, const Integer &e, const Integer &d,
				  const Integer &p, const Integer &q, const Integer &dp, const Integer &dq, const Integer &u)
		: PublicKeyBaseTemplate<InvertibleRSAFunction>(
			InvertibleRSAFunction(n, e, d, p, q, dp, dq, u)) {}

	RSAPrivateKeyTemplate(RandomNumberGenerator &rng, unsigned int keybits, const Integer &eStart=17)
		: PublicKeyBaseTemplate<InvertibleRSAFunction>(
			InvertibleRSAFunction(rng, keybits, eStart)) {}

	RSAPrivateKeyTemplate(BufferedTransformation &bt)
		: PublicKeyBaseTemplate<InvertibleRSAFunction>(bt) {}
};

template <class B, class V>
class RSAPublicKeyTemplate : public B
{
public:
	RSAPublicKeyTemplate(const Integer &n, const Integer &e)
		: PublicKeyBaseTemplate<RSAFunction>(RSAFunction(n, e)) {}

	RSAPublicKeyTemplate(const V &priv)
		: PublicKeyBaseTemplate<RSAFunction>(priv.GetTrapdoorFunction()) {}

	RSAPublicKeyTemplate(BufferedTransformation &bt)
		: PublicKeyBaseTemplate<RSAFunction>(bt) {}
};

// The two RSA encryption schemes defined in PKCS #1 v2.0
typedef RSAPrivateKeyTemplate<DecryptorTemplate<PKCS_EncryptionPaddingScheme, InvertibleRSAFunction> >
	RSAES_PKCS1v15_Decryptor;
typedef RSAPublicKeyTemplate<EncryptorTemplate<PKCS_EncryptionPaddingScheme, RSAFunction>, RSAES_PKCS1v15_Decryptor>
	RSAES_PKCS1v15_Encryptor;

typedef RSAPrivateKeyTemplate<DecryptorTemplate<OAEP<SHA>, InvertibleRSAFunction> >
	RSAES_OAEP_SHA_Decryptor;
typedef RSAPublicKeyTemplate<EncryptorTemplate<OAEP<SHA>, RSAFunction>, RSAES_OAEP_SHA_Decryptor>
	RSAES_OAEP_SHA_Encryptor;

// The three RSA signature schemes defined in PKCS #1 v2.0
typedef RSAPrivateKeyTemplate<SignerTemplate<DigestSignerTemplate<PKCS_SignaturePaddingScheme, InvertibleRSAFunction>, PKCS_DecoratedHashModule<SHA> > >
	RSASSA_PKCS1v15_SHA_Signer;
typedef RSAPublicKeyTemplate<VerifierTemplate<DigestVerifierTemplate<PKCS_SignaturePaddingScheme, RSAFunction>, PKCS_DecoratedHashModule<SHA> >, RSASSA_PKCS1v15_SHA_Signer>
	RSASSA_PKCS1v15_SHA_Verifier;

typedef RSAPrivateKeyTemplate<SignerTemplate<DigestSignerTemplate<PKCS_SignaturePaddingScheme, InvertibleRSAFunction>, PKCS_DecoratedHashModule<MD2> > >
	RSASSA_PKCS1v15_MD2_Signer;
typedef RSAPublicKeyTemplate<VerifierTemplate<DigestVerifierTemplate<PKCS_SignaturePaddingScheme, RSAFunction>, PKCS_DecoratedHashModule<MD2> >, RSASSA_PKCS1v15_MD2_Signer>
	RSASSA_PKCS1v15_MD2_Verifier;

typedef RSAPrivateKeyTemplate<SignerTemplate<DigestSignerTemplate<PKCS_SignaturePaddingScheme, InvertibleRSAFunction>, PKCS_DecoratedHashModule<MD5> > >
	RSASSA_PKCS1v15_MD5_Signer;
typedef RSAPublicKeyTemplate<VerifierTemplate<DigestVerifierTemplate<PKCS_SignaturePaddingScheme, RSAFunction>, PKCS_DecoratedHashModule<MD5> >, RSASSA_PKCS1v15_MD5_Signer>
	RSASSA_PKCS1v15_MD5_Verifier;

NAMESPACE_END

#endif
