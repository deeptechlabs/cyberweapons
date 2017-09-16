#ifndef CRYPTOPP_OAEP_H
#define CRYPTOPP_OAEP_H

#include "pubkey.h"

NAMESPACE_BEGIN(CryptoPP)

// defined in misc.cpp
extern byte OAEP_P_DEFAULT[];

// EME-OAEP
template <class H, class MGF=MGF1<H>, byte *P=OAEP_P_DEFAULT, unsigned int PLen=0>
class OAEP
{
public:
	unsigned int MaxUnpaddedLength(unsigned int paddedLength) const;
	void Pad(RandomNumberGenerator &rng, const byte *raw, unsigned int inputLength, byte *padded, unsigned int paddedLength) const;
	unsigned int Unpad(const byte *padded, unsigned int paddedLength, byte *raw) const;
};

NAMESPACE_END

#endif
