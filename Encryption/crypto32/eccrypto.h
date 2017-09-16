#ifndef CRYPTOPP_ECCRYPTO_H
#define CRYPTOPP_ECCRTPTO_H

#include "pubkey.h"
#include "integer.h"

NAMESPACE_BEGIN(CryptoPP)

/* The following classes are explicitly instantiated in eccrypto.cpp

	ECPublicKey<EC2N>;
	ECPublicKey<ECP>;
	ECPrivateKey<EC2N>;
	ECPrivateKey<ECP>;
	ECKEP<EC2N>;
	ECKEP<ECP>;
*/

template <class T> class EcPrecomputation;

// VC50 workaround
typedef PK_WithPrecomputation<PK_FixedLengthEncryptor> PKWPFLE;
typedef PK_WithPrecomputation<DigestVerifier> PKWDV;

enum ECSignatureScheme {ECNR, ECDSA};

template <class EC, ECSignatureScheme SS = ECNR>
class ECPublicKey : public PKWPFLE, public PKWDV
{
public:
	typedef typename EC::Point Point;

	ECPublicKey(const EC &E, const Point &P, const Point &Q, const Integer &orderP);
	~ECPublicKey();

/*
	// TODO: these are not implemented yet because there is no standard way to encoding EC keys
	ECPublicKey(BufferedTransformation &bt);
	void DEREncode(BufferedTransformation &bt) const;
*/

	void Precompute(unsigned int precomputationStorage=16);
	void LoadPrecomputation(BufferedTransformation &storedPrecomputation);
	void SavePrecomputation(BufferedTransformation &storedPrecomputation) const;

	void Encrypt(RandomNumberGenerator &rng, const byte *plainText, unsigned int plainTextLength, byte *cipherText);
	bool VerifyDigest(const byte *digest, unsigned int digestLen, const byte *signature) const;

	unsigned int MaxPlainTextLength() const {return l-2;}
	unsigned int CipherTextLength() const {return 3*l+1;}
	unsigned int MaxDigestLength() const {return 0xffff;}
	unsigned int DigestSignatureLength() const {return 2*f;}

	const Point& BasePoint() const {return P;}
	const Point& PublicPoint() const {return Q;}

	// exposed for validation testing
	bool RawVerify(const Integer &e, const Integer &r, const Integer &s) const;

protected:
	unsigned ExponentBitLength() const {return n.BitCount();}
	Integer EncodeDigest(const byte *digest, unsigned int digestLen) const;

	EC ec;
	Point P;
	Point Q;
	Integer n;
	EcPrecomputation<EC> Ppc, Qpc;
	unsigned int l, f;
};

template <class EC, ECSignatureScheme SS = ECNR>
class ECPrivateKey : public ECPublicKey<EC, SS>, public PK_FixedLengthDecryptor, public PK_WithPrecomputation<DigestSigner>
{
public:
	typedef typename EC::Point Point;

	ECPrivateKey(const EC &E, const Point &P, const Point &Q, const Integer &orderP, const Integer &d)
		: ECPublicKey<EC, SS>(E, P, Q, orderP), d(d) {}
	// generate a random private key
	ECPrivateKey(RandomNumberGenerator &rng, const EC &E, const Point &P, const Integer &orderP)
		: ECPublicKey<EC, SS>(E, P, P, orderP) {Randomize(rng);}
	~ECPrivateKey();

/*
	// TODO: these are not implemented yet because there is no standard way to encoding EC keys
	ECPrivateKey(BufferedTransformation &bt);
	void DEREncode(BufferedTransformation &bt) const;
*/

	unsigned int Decrypt(const byte *cipherText, byte *plainText);
	void SignDigest(RandomNumberGenerator &, const byte *digest, unsigned int digestLen, byte *signature) const;

	// exposed for validation testing
	void RawSign(const Integer &k, const Integer &e, Integer &r, Integer &s) const;

protected:
	typedef typename EC::FieldElement FieldElement;
	void Randomize(RandomNumberGenerator &rng);
	Integer d;
};

template <class EC, class H, ECSignatureScheme SS = ECNR>
class ECSigner : public SignerTemplate<ECPrivateKey<EC, SS>, H>, public PK_WithPrecomputation<PK_Signer>
{
	typedef SignerTemplate<ECPrivateKey<EC, SS>, H> Base;
public:
	typedef typename EC::Point Point;

	ECSigner(const EC &E, const Point &P, const Point &Q, const Integer &orderP, const Integer &d)
		: Base(ECPrivateKey<EC, SS>(E, P, Q, orderP, d)) {}
	// generate a random private key
	ECSigner(RandomNumberGenerator &rng, const EC &E, const Point &P, const Integer &orderP)
		: Base(ECPrivateKey<EC, SS>(rng, E, P, orderP)) {}
};

template <class EC, class H, ECSignatureScheme SS = ECNR>
class ECVerifier : public VerifierTemplate<ECPublicKey<EC, SS>, H>, public PK_WithPrecomputation<PK_Verifier>
{
	typedef VerifierTemplate<ECPublicKey<EC, SS>, H> Base;
public:
	typedef typename EC::Point Point;

	ECVerifier(const EC &E, const Point &P, const Point &Q, const Integer &orderP)
		: Base(ECPublicKey<EC, SS>(E, P, Q, orderP)) {}
	ECVerifier(const ECSigner<EC, H, SS> &priv)
		: Base(priv) {}
};

// Elliptic Curve Diffie-Hellman with Cofactor Multiplication
template <class EC>
class ECDHC : public PK_WithPrecomputation<PK_SimpleKeyAgreementDomain>
{
public:
	typedef typename EC::Point Point;

	// G is a point of prime order r, k is order of ec divided by r
	ECDHC(const EC &ec, const Point &G, const Integer &r, const Integer &k);
	~ECDHC();

	void Precompute(unsigned int precomputationStorage=16);
	void LoadPrecomputation(BufferedTransformation &storedPrecomputation);
	void SavePrecomputation(BufferedTransformation &storedPrecomputation) const;

	bool ValidateDomainParameters(RandomNumberGenerator &rng) const;
	unsigned int AgreedValueLength() const {return ec.GetField().MaxElementByteLength();}
	unsigned int PrivateKeyLength() const {return r.ByteCount();}
	unsigned int PublicKeyLength() const {return ec.EncodedPointSize();}

	void GenerateKeyPair(RandomNumberGenerator &rng, byte *privateKey, byte *publicKey) const;
	bool Agree(byte *agreedValue, const byte *privateKey, const byte *otherPublicKey, bool validateOtherPublicKey=true) const;

protected:
	EC ec;
	Point G;
	Integer r, k;
	EcPrecomputation<EC> Gpc;
};

// Elliptic Curve Menezes-Qu-Vanstone with Cofactor Multiplication
template <class EC>
class ECMQVC : public PK_WithPrecomputation<PK_AuthenticatedKeyAgreementDomain>
{
public:
	typedef typename EC::Point Point;

	// G is a point of prime order r, k is order of ec divided by r
	ECMQVC(const EC &ec, const Point &G, const Integer &r, const Integer &k);
	~ECMQVC();

	void Precompute(unsigned int precomputationStorage=16);
	void LoadPrecomputation(BufferedTransformation &storedPrecomputation);
	void SavePrecomputation(BufferedTransformation &storedPrecomputation) const;

	bool ValidateDomainParameters(RandomNumberGenerator &rng) const;
	unsigned int AgreedValueLength() const {return ec.GetField().MaxElementByteLength();}

	unsigned int StaticPrivateKeyLength() const {return r.ByteCount();}
	unsigned int StaticPublicKeyLength() const {return ec.EncodedPointSize();}
	void GenerateStaticKeyPair(RandomNumberGenerator &rng, byte *privateKey, byte *publicKey) const;

	unsigned int EphemeralPrivateKeyLength() const {return r.ByteCount()+ec.EncodedPointSize();}
	unsigned int EphemeralPublicKeyLength() const {return ec.EncodedPointSize();}
	void GenerateEphemeralKeyPair(RandomNumberGenerator &rng, byte *privateKey, byte *publicKey) const;

	bool Agree(byte *agreedValue,
		const byte *staticPrivateKey, const byte *ephemeralPrivateKey, 
		const byte *staticOtherPublicKey, const byte *ephemeralOtherPublicKey,
		bool validateStaticOtherPublicKey=true) const;

protected:
	EC ec;
	Point G;
	Integer r, k;
	EcPrecomputation<EC> Gpc;
};

NAMESPACE_END

#endif
