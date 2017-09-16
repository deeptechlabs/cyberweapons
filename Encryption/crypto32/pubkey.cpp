#include "pch.h"
#include "pubkey.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

#define INSTANTIATE_PUBKEY_CRYPTO_TEMPLATES_MACRO(E, F, I) \
template class DecryptorTemplate<E, I >;\
template class EncryptorTemplate<E, F >;

#define INSTANTIATE_PUBKEY_SIG_TEMPLATES_MACRO(S, F, I) \
template class DigestSignerTemplate<S, I >;\
template class DigestVerifierTemplate<S, F >;

#define INSTANTIATE_PUBKEY_TEMPLATES_MACRO(E, S, F, I)	\
INSTANTIATE_PUBKEY_CRYPTO_TEMPLATES_MACRO(E, F, I)      \
INSTANTIATE_PUBKEY_SIG_TEMPLATES_MACRO(S, F, I)

template <class P, class F>
unsigned int DecryptorTemplate<P,F>::Decrypt(const byte *cipherText, byte *plainText)
{
	SecByteBlock paddedBlock(PaddedBlockByteLength());
	f.CalculateInverse(Integer(cipherText, CipherTextLength())).Encode(paddedBlock, paddedBlock.size);
	return pad.Unpad(paddedBlock, PaddedBlockBitLength(), plainText);
}

template <class P, class F>
void EncryptorTemplate<P,F>::Encrypt(RandomNumberGenerator &rng, const byte *plainText, unsigned int plainTextLength, byte *cipherText)
{
	assert(plainTextLength <= MaxPlainTextLength());

	SecByteBlock paddedBlock(PaddedBlockByteLength());
	pad.Pad(rng, plainText, plainTextLength, paddedBlock, PaddedBlockBitLength());
	f.ApplyFunction(Integer(paddedBlock, paddedBlock.size)).Encode(cipherText, CipherTextLength());
}

template <class P, class F>
void DigestSignerTemplate<P,F>::SignDigest(RandomNumberGenerator &rng, const byte *digest, unsigned int digestLength, byte *signature) const
{
	assert(digestLength <= MaxDigestLength());

	SecByteBlock paddedBlock(PaddedBlockByteLength());
	pad.Pad(rng, digest, digestLength, paddedBlock, PaddedBlockBitLength());
	f.CalculateInverse(Integer(paddedBlock, paddedBlock.size)).Encode(signature, DigestSignatureLength());
}

template <class P, class F>
bool DigestVerifierTemplate<P,F>::VerifyDigest(const byte *digest, unsigned int digestLen, const byte *signature) const
{
	SecByteBlock paddedBlock(PaddedBlockByteLength());
	f.ApplyFunction(Integer(signature, DigestSignatureLength())).Encode(paddedBlock, paddedBlock.size);
	SecByteBlock recoveredDigest(MaxDigestLength());
	unsigned int recoveredDigestLen = pad.Unpad(paddedBlock, PaddedBlockBitLength(), recoveredDigest);
	return digestLen == recoveredDigestLen && memcmp(digest, recoveredDigest, digestLen) == 0;
}

NAMESPACE_END
