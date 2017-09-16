#ifndef CRYPTOPP_PKCSPAD_H
#define CRYPTOPP_PKCSPAD_H

#include "cryptlib.h"
#include "pubkey.h"

NAMESPACE_BEGIN(CryptoPP)

// EME-PKCS1-v1_5
class PKCS_EncryptionPaddingScheme
{
public:
	unsigned int MaxUnpaddedLength(unsigned int paddedLength) const;
	void Pad(RandomNumberGenerator &rng, const byte *raw, unsigned int inputLength, byte *padded, unsigned int paddedLength) const;
	unsigned int Unpad(const byte *padded, unsigned int paddedLength, byte *raw) const;
};

// EMSA-PKCS1-v1_5
class PKCS_SignaturePaddingScheme
{
public:
	unsigned int MaxUnpaddedLength(unsigned int paddedLength) const;
	void Pad(RandomNumberGenerator &rng, const byte *raw, unsigned int inputLength, byte *padded, unsigned int paddedLength) const;
	unsigned int Unpad(const byte *padded, unsigned int paddedLength, byte *raw) const;
};

template <class H>
class PKCS_DecoratedHashModule : public HashModule
{
public:
	void Update(const byte *input, unsigned int length)
		{h.Update(input, length);}
	unsigned int DigestSize() const;
	void Final(byte *digest);

private:
	H h;
};

template <class H> struct PKCS_DigestDecoration
{
	static const byte decoration[];
	static const unsigned int length;
};

// PKCS_DecoratedHashModule can be instantiated with the following three
// classes as specified in PKCS#1 v2.0.
class SHA;
class MD2;
class MD5;

template <class H>
void PKCS_DecoratedHashModule<H>::Final(byte *digest)
{
	const unsigned int decorationLen = PKCS_DigestDecoration<H>::length;
	memcpy(digest, PKCS_DigestDecoration<H>::decoration, decorationLen);
	h.Final(digest+decorationLen);
}

template <class H>
unsigned int PKCS_DecoratedHashModule<H>::DigestSize() const
{
	return h.DigestSize() + PKCS_DigestDecoration<H>::length;
}

NAMESPACE_END

#endif
