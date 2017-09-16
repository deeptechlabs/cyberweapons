// lubyrack.h - written and placed in the public domain by Wei Dai

#ifndef CRYPTOPP_LUBYRACK_H
#define CRYPTOPP_LUBYRACK_H

#include "cryptlib.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

template <class T> class LRBase : public BlockTransformation
{
public:
	enum {KEYLENGTH=16};    // default key length

protected:
	LRBase(const byte *userKey, unsigned int keyLen);
	unsigned int BlockSize() const {return 2*S;}
	static unsigned int KeyLength(unsigned int keylength)
		{return keylength < 1 ? 1 : keylength;}

	const unsigned int S;    // block size / 2
	const unsigned int L;    // key length / 2
	SecByteBlock key;

	mutable T hm;
	mutable SecByteBlock buffer;
};

template <class T> class LREncryption : public LRBase<T>
{
public:
	// keyLen must be even
	LREncryption(const byte *userKey, int keyLen=LRBase<T>::KEYLENGTH)
		: LRBase<T>(userKey, keyLen) {}

	void ProcessBlock(byte * inoutBlock) const
		{LREncryption<T>::ProcessBlock(inoutBlock, inoutBlock);}

	void ProcessBlock(const byte *inBlock, byte * outBlock) const;
};

template <class T> class LRDecryption : public LRBase<T>
{
public:
	// keyLen must be even
	LRDecryption(const byte *userKey, int keyLen=LRBase<T>::KEYLENGTH)
		: LRBase<T>(userKey, keyLen) {}

	void ProcessBlock(byte * inoutBlock) const
		{LRDecryption<T>::ProcessBlock(inoutBlock, inoutBlock);}

	void ProcessBlock(const byte *inBlock, byte * outBlock) const;
};

template <class T> LRBase<T>::LRBase(const byte *userKey, unsigned int keyLen)
: S(T::DIGESTSIZE), L(keyLen/2), key(2*L), buffer(2*S)
{
	memcpy(key, userKey, 2*L);
}

#define KL key
#define KR key+L
#define BL buffer
#define BR buffer+S
#define IL inBlock
#define IR inBlock+S
#define OL outBlock
#define OR outBlock+S

template <class T> void LREncryption<T>::ProcessBlock(const byte *inBlock, byte * outBlock) const
{
	hm.Update(KL, L);
	hm.Update(IL, S);
	hm.Final(BR);
	xorbuf(BR, IR, S);

	hm.Update(KR, L);
	hm.Update(BR, S);
	hm.Final(BL);
	xorbuf(BL, IL, S);

	hm.Update(KL, L);
	hm.Update(BL, S);
	hm.Final(OR);
	xorbuf(OR, BR, S);

	hm.Update(KR, L);
	hm.Update(OR, S);
	hm.Final(OL);
	xorbuf(OL, BL, S);
}

template <class T> void LRDecryption<T>::ProcessBlock(const byte *inBlock, byte * outBlock) const
{
	hm.Update(KR, L);
	hm.Update(IR, S);
	hm.Final(BL);
	xorbuf(BL, IL, S);

	hm.Update(KL, L);
	hm.Update(BL, S);
	hm.Final(BR);
	xorbuf(BR, IR, S);

	hm.Update(KR, L);
	hm.Update(BR, S);
	hm.Final(OL);
	xorbuf(OL, BL, S);

	hm.Update(KL, L);
	hm.Update(OL, S);
	hm.Final(OR);
	xorbuf(OR, BR, S);
}

#undef KL
#undef KR
#undef BL
#undef BR
#undef IL
#undef IR
#undef OL
#undef OR

NAMESPACE_END

#endif
