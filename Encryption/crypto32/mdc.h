 // mdc.h - written and placed in the public domain by Wei Dai

#ifndef CRYPTOPP_MDC_H
#define CRYPTOPP_MDC_H

#include "cryptlib.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

template <class T> class MDC : public BlockTransformation
{
public:
	MDC(const byte *userKey, unsigned int = 0)
		: key(KEYLENGTH/4)
	{
		T::CorrectEndianess(key, (word32 *)userKey, KEYLENGTH);
	}

	void ProcessBlock(byte *inoutBlock) const
	{
		T::CorrectEndianess((word32 *)inoutBlock, (word32 *)inoutBlock, BLOCKSIZE);
		T::Transform((word32 *)inoutBlock, key);
		T::CorrectEndianess((word32 *)inoutBlock, (word32 *)inoutBlock, BLOCKSIZE);
	}

	void ProcessBlock(const byte *inBlock, byte *outBlock) const
	{
		T::CorrectEndianess((word32 *)outBlock, (word32 *)inBlock, BLOCKSIZE);
		T::Transform((word32 *)outBlock, key);
		T::CorrectEndianess((word32 *)outBlock, (word32 *)outBlock, BLOCKSIZE);
	}

	unsigned int BlockSize() const {return BLOCKSIZE;}
	static unsigned int KeyLength(unsigned int keylength) {return KEYLENGTH;}

#ifdef __BCPLUSPLUS__
	static const unsigned int KEYLENGTH=T::DATASIZE;
    static const unsigned int BLOCKSIZE=T::DIGESTSIZE;
#else
	enum {KEYLENGTH=T::DATASIZE, BLOCKSIZE=T::DIGESTSIZE};
#endif

private:
	SecBlock<word32> key;
};

NAMESPACE_END

#endif
