#ifndef CRYPTOPP_PUBKEY_H
#define CRYPTOPP_PUBKEY_H

#include "cryptlib.h"
#include "misc.h"
#include <memory>
#include <assert.h>

NAMESPACE_BEGIN(CryptoPP)

class Integer;

class TrapdoorFunction
{
public:
	virtual ~TrapdoorFunction() {}

	virtual Integer ApplyFunction(const Integer &x) const =0;
	virtual Integer MaxPreimage() const =0;
	virtual Integer MaxImage() const =0;
};

class InvertibleTrapdoorFunction : virtual public TrapdoorFunction
{
public:
	virtual Integer CalculateInverse(const Integer &x) const =0;
};

class PaddingScheme
{
public:
	virtual ~PaddingScheme() {}

	virtual unsigned int MaxUnpaddedLength(unsigned int paddedLength) const =0;

	virtual void Pad(RandomNumberGenerator &rng, const byte *raw, unsigned int inputLength, byte *padded, unsigned int paddedLength) const =0;
	// returns length of raw
	virtual unsigned int Unpad(const byte *padded, unsigned int paddedLength, byte *raw) const =0;
};

// ********************************************************

template <class H>
class MGF1
{
public:
	static void GenerateAndMask(byte *output, unsigned int outputLength, const byte *input, unsigned int inputLength);
};

template <class H>
void MGF1<H>::GenerateAndMask(byte *output, unsigned int outputLength, const byte *input, unsigned int inputLength)
{
	H h;
	SecByteBlock buf(STDMAX(4U, (unsigned int)H::DIGESTSIZE));
	word32 counter = 0;

	while (outputLength)
	{
		h.Update(input, inputLength);
		buf[0] = byte(counter >> 3*8);
		buf[1] = byte(counter >> 2*8);
		buf[2] = byte(counter >> 1*8);
		buf[3] = byte(counter);
		h.Update(buf, 4);
		h.Final(buf);

		unsigned int xorLen = STDMIN((unsigned int)H::DIGESTSIZE, outputLength);
		xorbuf(output, buf, xorLen);

		output += xorLen;
		outputLength -= xorLen;
		counter++;
	}
}

// ********************************************************

template <class F>
class PublicKeyBaseTemplate
{
public:
	PublicKeyBaseTemplate(const F &f) : f(f) {}
	PublicKeyBaseTemplate(BufferedTransformation &bt) : f(bt) {}
	void DEREncode(BufferedTransformation &bt) const {f.DEREncode(bt);}

	const F & GetTrapdoorFunction() const {return f;}

protected:
	// a hack to avoid having to write constructors for non-concrete derived classes
	PublicKeyBaseTemplate() : f(*(F*)0) {assert(false);}	// should never be called
	virtual unsigned int PaddedBlockBitLength() const =0;
	unsigned int PaddedBlockByteLength() const {return bitsToBytes(PaddedBlockBitLength());}

	F f;
};

// ********************************************************

template <class P, class F>
class CryptoSystemBaseTemplate : virtual public PK_FixedLengthCryptoSystem, virtual public PublicKeyBaseTemplate<F>
{
public:
	unsigned int MaxPlainTextLength() const {return pad.MaxUnpaddedLength(PaddedBlockBitLength());}
	unsigned int CipherTextLength() const {return f.MaxImage().ByteCount();}

	P pad;

protected:
	CryptoSystemBaseTemplate() {}
	unsigned int PaddedBlockBitLength() const {return f.MaxPreimage().BitCount()-1;}
};

template <class P, class F>
class DecryptorTemplate : public PK_FixedLengthDecryptor, public CryptoSystemBaseTemplate<P, F>
{
public:
	~DecryptorTemplate() {}
	unsigned int Decrypt(const byte *cipherText, byte *plainText);

protected:
	DecryptorTemplate() {}
};

template <class P, class T>
class EncryptorTemplate : public PK_FixedLengthEncryptor, public CryptoSystemBaseTemplate<P, T>
{
public:
	~EncryptorTemplate() {}
	void Encrypt(RandomNumberGenerator &rng, const byte *plainText, unsigned int plainTextLength, byte *cipherText);

protected:
	EncryptorTemplate() {}
};

// ********************************************************

class DigestSignatureSystem
{
public:
	virtual ~DigestSignatureSystem() {};
	virtual unsigned int MaxDigestLength() const =0;
	virtual unsigned int DigestSignatureLength() const =0;
};

class DigestSigner : public virtual DigestSignatureSystem
{
public:
	virtual void SignDigest(RandomNumberGenerator &rng, const byte *digest, unsigned int digestLen, byte *signature) const =0;
};

class DigestVerifier : public virtual DigestSignatureSystem
{
public:
	virtual bool VerifyDigest(const byte *digest, unsigned int digestLen, const byte *sig) const =0;
};

template <class P, class T>
class DigestSignatureSystemBaseTemplate : virtual public DigestSignatureSystem, virtual public PublicKeyBaseTemplate<T>
{
public:
	unsigned int MaxDigestLength() const {return pad.MaxUnpaddedLength(PaddedBlockBitLength());}
	unsigned int DigestSignatureLength() const {return f.MaxPreimage().ByteCount();}

	P pad;

protected:
	DigestSignatureSystemBaseTemplate() {}
	unsigned int PaddedBlockBitLength() const {return f.MaxImage().BitCount()-1;}
};

template <class P, class T>
class DigestSignerTemplate : public DigestSigner, public DigestSignatureSystemBaseTemplate<P, T>
{
public:
	~DigestSignerTemplate() {}
	void SignDigest(RandomNumberGenerator &rng, const byte *message, unsigned int messageLength, byte *signature) const;

protected:
	DigestSignerTemplate() {}
};

template <class P, class T>
class DigestVerifierTemplate : public DigestVerifier, public DigestSignatureSystemBaseTemplate<P, T>
{
public:
	~DigestVerifierTemplate() {}
	bool VerifyDigest(const byte *digest, unsigned int digestLen, const byte *sig) const;

protected:
	DigestVerifierTemplate() {}
};

// ********************************************************

template <class S, class H>
class SignatureSystemBaseTemplate : virtual public PK_SignatureSystem, public S
{
public:
	unsigned int SignatureLength() const {return DigestSignatureLength();}
	HashModule * NewMessageAccumulator() const {return new H;}

protected:
	SignatureSystemBaseTemplate(const S &s) : S(s) {}
	SignatureSystemBaseTemplate(BufferedTransformation &bt) : S(bt) {}
	SignatureSystemBaseTemplate() {}
};

template <class S, class H>
class SignerTemplate : virtual public PK_Signer, public SignatureSystemBaseTemplate<S, H>
{
public:
	~SignerTemplate() {}
	void Sign(RandomNumberGenerator &rng, HashModule *messageAccumulator, byte *signature) const;

protected:
	SignerTemplate(const S &s) : SignatureSystemBaseTemplate<S, H>(s) {}
	SignerTemplate(BufferedTransformation &bt) : SignatureSystemBaseTemplate<S, H>(bt) {}
	SignerTemplate() {}
};

template <class S, class H>
class VerifierTemplate : virtual public PK_Verifier, public SignatureSystemBaseTemplate<S, H>
{
public:
	~VerifierTemplate() {}
	bool Verify(HashModule *messageAccumulator, const byte *sig) const;

protected:
	VerifierTemplate(const S &s) : SignatureSystemBaseTemplate<S, H>(s) {}
	VerifierTemplate(BufferedTransformation &bt) : SignatureSystemBaseTemplate<S, H>(bt) {}
	VerifierTemplate() {}
};

template <class S, class H>
void SignerTemplate<S,H>::Sign(RandomNumberGenerator &rng, HashModule *messageAccumulator, byte *signature) const
{
	std::auto_ptr<HashModule> ma(messageAccumulator);
	if (ma->DigestSize() > MaxDigestLength())
		throw KeyTooShort();
	SecByteBlock digest(ma->DigestSize());
	ma->Final(digest);
	SignDigest(rng, digest, digest.size, signature);
}

template <class S, class H>
bool VerifierTemplate<S,H>::Verify(HashModule *messageAccumulator, const byte *sig) const
{
	std::auto_ptr<HashModule> ma(messageAccumulator);
	SecByteBlock digest(ma->DigestSize());
	ma->Final(digest);
	return VerifyDigest(digest, digest.size, sig);
}

// ********************************************************

class SignatureEncodingMethodWithRecovery : public HashModule
{
public:
	void Final(byte *digest) {}
	virtual void Encode(RandomNumberGenerator &rng, byte *representative) =0;
	virtual bool Verify(const byte *representative) =0;
	virtual unsigned int Decode(byte *message) =0;
	virtual unsigned int MaximumRecoverableLength() const =0;
};

template <class F, class H>
class SignatureSystemWithRecoveryBaseTemplate : virtual public PK_SignatureSystemWithRecovery, virtual public PublicKeyBaseTemplate<F>
{
public:
	unsigned int SignatureLength() const {return f.MaxPreimage().ByteCount();}
	HashModule * NewMessageAccumulator() const {return new H(PaddedBlockBitLength());}
	unsigned int MaximumRecoverableLength() const {return H::MaximumRecoverableLength(PaddedBlockBitLength());}
	bool AllowLeftoverMessage() const {return H::AllowLeftoverMessage();}

protected:
	unsigned int PaddedBlockBitLength() const {return f.MaxImage().BitCount()-1;}
};

template <class F, class H>
class SignerWithRecoveryTemplate : virtual public PK_SignerWithRecovery, public SignatureSystemWithRecoveryBaseTemplate<F, H>
{
public:
	void Sign(RandomNumberGenerator &rng, HashModule *messageAccumulator, byte *signature) const;
};

template <class F, class H>
class VerifierWithRecoveryTemplate : virtual public PK_VerifierWithRecovery, public SignatureSystemWithRecoveryBaseTemplate<F, H>
{
public:
	bool Verify(HashModule *messageAccumulator, const byte *sig) const;
	HashModule * NewLeftoverMessageAccumulator(const byte *signature) const;
	unsigned int PartialRecover(HashModule *leftoverMessageAccumulator, byte *recoveredMessage) const;
	unsigned int Recover(const byte *signature, byte *recoveredMessage) const;
};

template <class F, class H>
void SignerWithRecoveryTemplate<F,H>::Sign(RandomNumberGenerator &rng, HashModule *messageAccumulator, byte *signature) const
{
	std::auto_ptr<H> ma(static_cast<H*>(messageAccumulator));
	if (ma->MaximumRecoverableLength() == 0)
		throw KeyTooShort();
	SecByteBlock representative(PaddedBlockByteLength());
	ma->Encode(rng, representative);
	f.CalculateInverse(Integer(representative, representative.size)).Encode(signature, SignatureLength());
}

template <class F, class H>
bool VerifierWithRecoveryTemplate<F,H>::Verify(HashModule *messageAccumulator, const byte *signature) const
{
	std::auto_ptr<H> ma(static_cast<H*>(messageAccumulator));
	SecByteBlock representative(PaddedBlockByteLength());
	f.ApplyFunction(Integer(signature, SignatureLength())).Encode(representative, representative.size);
	return ma->Verify(representative);
}

template <class F, class H>
HashModule * VerifierWithRecoveryTemplate<F,H>::NewLeftoverMessageAccumulator(const byte *signature) const
{
	SecByteBlock representative(PaddedBlockByteLength());
	f.ApplyFunction(Integer(signature, SignatureLength())).Encode(representative, representative.size);
	return new H(representative, PaddedBlockBitLength());
}

template <class F, class H>
unsigned int VerifierWithRecoveryTemplate<F,H>::PartialRecover(HashModule *messageAccumulator, byte *recoveredMessage) const
{
	std::auto_ptr<H> ma(static_cast<H*>(messageAccumulator));
	return ma->Decode(recoveredMessage);
}

template <class F, class H>
unsigned int VerifierWithRecoveryTemplate<F,H>::Recover(const byte *signature, byte *recoveredMessage) const
{
	return PartialRecover(NewLeftoverMessageAccumulator(signature), recoveredMessage);
}

NAMESPACE_END

#endif
