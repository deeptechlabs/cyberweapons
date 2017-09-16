#ifndef CRYPTOPP_MISC_H
#define CRYPTOPP_MISC_H

#include "config.h"
#include <assert.h>
#include <string.h>		// CodeWarrior doesn't have memory.h
#include <algorithm>

#ifdef INTEL_INTRINSICS
#include <stdlib.h>
#endif

NAMESPACE_BEGIN(CryptoPP)

// ************** misc functions ***************

#ifdef _MSC_VER
#define GETBYTE(x, y) (((byte *)&(x))[y])
#else
#define GETBYTE(x, y) (unsigned int)(((x)>>(8*(y)))&255)
#endif

unsigned int Parity(unsigned long);
unsigned int BytePrecision(unsigned long);
unsigned int BitPrecision(unsigned long);
unsigned long Crop(unsigned long, unsigned int size);

inline unsigned int bitsToBytes(unsigned int bitCount)
{
	return ((bitCount+7)/(8));
}

inline unsigned int bytesToWords(unsigned int byteCount)
{
	return ((byteCount+WORD_SIZE-1)/WORD_SIZE);
}

inline unsigned int bitsToWords(unsigned int bitCount)
{
	return ((bitCount+WORD_BITS-1)/(WORD_BITS));
}

void xorbuf(byte *buf, const byte *mask, unsigned int count);
void xorbuf(byte *output, const byte *input, const byte *mask, unsigned int count);

// ************** rotate functions ***************

template <class T> inline T rotlFixed(T x, unsigned int y)
{
	assert(y < sizeof(T)*8);
	return (x<<y) | (x>>(sizeof(T)*8-y));
}

template <class T> inline T rotrFixed(T x, unsigned int y)
{
	assert(y < sizeof(T)*8);
	return (x>>y) | (x<<(sizeof(T)*8-y));
}

template <class T> inline T rotlVariable(T x, unsigned int y)
{
	assert(y < sizeof(T)*8);
	return (x<<y) | (x>>(sizeof(T)*8-y));
}

template <class T> inline T rotrVariable(T x, unsigned int y)
{
	assert(y < sizeof(T)*8);
	return (x>>y) | (x<<(sizeof(T)*8-y));
}

template <class T> inline T rotlMod(T x, unsigned int y)
{
	y %= sizeof(T)*8;
	return (x<<y) | (x>>(sizeof(T)*8-y));
}

template <class T> inline T rotrMod(T x, unsigned int y)
{
	y %= sizeof(T)*8;
	return (x>>y) | (x<<(sizeof(T)*8-y));
}

#ifdef INTEL_INTRINSICS

template<> inline word32 rotlFixed<word32>(word32 x, unsigned int y)
{
	assert(y < 32);
	return _lrotl(x, y);
}

template<> inline word32 rotrFixed<word32>(word32 x, unsigned int y)
{
	assert(y < 32);
	return _lrotr(x, y);
}

template<> inline word32 rotlVariable<word32>(word32 x, unsigned int y)
{
	assert(y < 32);
	return _lrotl(x, y);
}

template<> inline word32 rotrVariable<word32>(word32 x, unsigned int y)
{
	assert(y < 32);
	return _lrotr(x, y);
}

template<> inline word32 rotlMod<word32>(word32 x, unsigned int y)
{
	return _lrotl(x, y);
}

template<> inline word32 rotrMod<word32>(word32 x, unsigned int y)
{
	return _lrotr(x, y);
}

#endif // #ifdef INTEL_INTRINSICS

#ifdef PPC_INTRINSICS

template<> inline word32 rotlFixed<word32>(word32 x, unsigned int y)
{
	assert(y < 32);
	return (__rlwinm(x,y,0,31));
}

template<> inline word32 rotrFixed<word32>(word32 x, unsigned int y)
{
	assert(y < 32);
	return (__rlwinm(x,32-y,0,31));
}

template<> inline word32 rotlVariable<word32>(word32 x, unsigned int y)
{
	assert(y < 32);
	return (__rlwnm(x,y,0,31));
}

template<> inline word32 rotrVariable<word32>(word32 x, unsigned int y)
{
	assert(y < 32);
	return (__rlwnm(x,32-y,0,31));
}

template<> inline word32 rotlMod<word32>(word32 x, unsigned int y)
{
	return (__rlwnm(x,y,0,31));
}

template<> inline word32 rotrMod<word32>(word32 x, unsigned int y)
{
	return (__rlwnm(x,32-y,0,31));
}

#endif // #ifdef PPC_INTRINSICS

// ************** endian reversal ***************

inline word16 byteReverse(word16 value)
{
	return rotlFixed(value, 8U);
}

inline word32 byteReverse(word32 value)
{
#ifdef PPC_INTRINSICS
	// PPC: load reverse indexed instruction
	return (word32)__lwbrx(&value,0);
#elif defined(FAST_ROTATE)
	// 5 instructions with rotate instruction, 9 without
	return (rotrFixed(value, 8U) & 0xff00ff00) | (rotlFixed(value, 8U) & 0x00ff00ff);
#else
	// 6 instructions with rotate instruction, 8 without
	value = ((value & 0xFF00FF00) >> 8) | ((value & 0x00FF00FF) << 8);
	return rotlFixed(value, 16U);
#endif
}

#ifdef WORD64_AVAILABLE
inline word64 byteReverse(word64 value)
{
#ifdef SLOW_WORD64
	return (dword(byteReverse(word32(value))) << 32) | byteReverse(word32(value>>32));
#else
	value = ((value & W64LIT(0xFF00FF00FF00FF00)) >> 8) | ((value & W64LIT(0x00FF00FF00FF00FF)) << 8);
	value = ((value & W64LIT(0xFFFF0000FFFF0000)) >> 16) | ((value & W64LIT(0x0000FFFF0000FFFF)) << 16);
	return rotlFixed(value, 32U);
#endif
}
#endif

template <class T>
void byteReverse(T *out, const T *in, unsigned int byteCount)
{
	unsigned int count = (byteCount+sizeof(T)-1)/sizeof(T);
	for (unsigned int i=0; i<count; i++)
		out[i] = byteReverse(in[i]);
}

template <class T>
inline void GetUserKeyLittleEndian(T *out, unsigned int outlen, const byte *in, unsigned int inlen)
{
	const unsigned int U = sizeof(T);
	assert(inlen <= outlen*U);
	memcpy(out, in, inlen);
	memset((byte *)out+inlen, 0, outlen*U-inlen);
#ifndef IS_LITTLE_ENDIAN
	byteReverse(out, out, inlen);
#endif
}

template <class T>
inline void GetUserKeyBigEndian(T *out, unsigned int outlen, const byte *in, unsigned int inlen)
{
	const unsigned int U = sizeof(T);
	assert(inlen <= outlen*U);
	memcpy(out, in, inlen);
	memset((byte *)out+inlen, 0, outlen*U-inlen);
#ifdef IS_LITTLE_ENDIAN
	byteReverse(out, out, inlen);
#endif
}

// Fetch 2 words from user's buffer into "a", "b" in LITTLE-endian order
template <class T>
inline void GetBlockLittleEndian(const byte *block, T &a, T &b)
{
#ifdef IS_LITTLE_ENDIAN
	a = ((T *)block)[0];
	b = ((T *)block)[1];
#else
	a = byteReverse(((T *)block)[0]);
	b = byteReverse(((T *)block)[1]);
#endif
}

// Put 2 words back into user's buffer in LITTLE-endian order
template <class T>
inline void PutBlockLittleEndian(byte *block, T a, T b)
{
#ifdef IS_LITTLE_ENDIAN
	((T *)block)[0] = a;
	((T *)block)[1] = b;
#else
	((T *)block)[0] = byteReverse(a);
	((T *)block)[1] = byteReverse(b);
#endif
}

// Fetch 4 words from user's buffer into "a", "b", "c", "d" in LITTLE-endian order
template <class T>
inline void GetBlockLittleEndian(const byte *block, T &a, T &b, T &c, T &d)
{
#ifdef IS_LITTLE_ENDIAN
	a = ((T *)block)[0];
	b = ((T *)block)[1];
	c = ((T *)block)[2];
	d = ((T *)block)[3];
#else
	a = byteReverse(((T *)block)[0]);
	b = byteReverse(((T *)block)[1]);
	c = byteReverse(((T *)block)[2]);
	d = byteReverse(((T *)block)[3]);
#endif
}

// Put 4 words back into user's buffer in LITTLE-endian order
template <class T>
inline void PutBlockLittleEndian(byte *block, T a, T b, T c, T d)
{
#ifdef IS_LITTLE_ENDIAN
	((T *)block)[0] = a;
	((T *)block)[1] = b;
	((T *)block)[2] = c;
	((T *)block)[3] = d;
#else
	((T *)block)[0] = byteReverse(a);
	((T *)block)[1] = byteReverse(b);
	((T *)block)[2] = byteReverse(c);
	((T *)block)[3] = byteReverse(d);
#endif
}

// Fetch 2 words from user's buffer into "a", "b" in BIG-endian order
template <class T>
inline void GetBlockBigEndian(const byte *block, T &a, T &b)
{
#ifndef IS_LITTLE_ENDIAN
	a = ((T *)block)[0];
	b = ((T *)block)[1];
#else
	a = byteReverse(((T *)block)[0]);
	b = byteReverse(((T *)block)[1]);
#endif
}

// Put 2 words back into user's buffer in BIG-endian order
template <class T>
inline void PutBlockBigEndian(byte *block, T a, T b)
{
#ifndef IS_LITTLE_ENDIAN
	((T *)block)[0] = a;
	((T *)block)[1] = b;
#else
	((T *)block)[0] = byteReverse(a);
	((T *)block)[1] = byteReverse(b);
#endif
}

// Fetch 4 words from user's buffer into "a", "b", "c", "d" in BIG-endian order
template <class T>
inline void GetBlockBigEndian(const byte *block, T &a, T &b, T &c, T &d)
{
#ifndef IS_LITTLE_ENDIAN
	a = ((T *)block)[0];
	b = ((T *)block)[1];
	c = ((T *)block)[2];
	d = ((T *)block)[3];
#else
	a = byteReverse(((T *)block)[0]);
	b = byteReverse(((T *)block)[1]);
	c = byteReverse(((T *)block)[2]);
	d = byteReverse(((T *)block)[3]);
#endif
}

// Put 4 words back into user's buffer in BIG-endian order
template <class T>
inline void PutBlockBigEndian(byte *block, T a, T b, T c, T d)
{
#ifndef IS_LITTLE_ENDIAN
	((T *)block)[0] = a;
	((T *)block)[1] = b;
	((T *)block)[2] = c;
	((T *)block)[3] = d;
#else
	((T *)block)[0] = byteReverse(a);
	((T *)block)[1] = byteReverse(b);
	((T *)block)[2] = byteReverse(c);
	((T *)block)[3] = byteReverse(d);
#endif
}

// ************** secure memory allocation ***************

#ifdef SECALLOC_DEFAULT
#define SecAlloc(type, number) (new type[(number)])
#define SecFree(ptr, number) (memset((ptr), 0, (number)*sizeof(*(ptr))), delete [] (ptr))
#else
#define SecAlloc(type, number) (new type[(number)])
#define SecFree(ptr, number) (delete [] (ptr))
#endif

template <class T> struct SecBlock
{
	SecBlock(unsigned int size=0)
		: size(size) {ptr = SecAlloc(T, size);}
	SecBlock(const SecBlock<T> &t)
		: size(t.size) {ptr = SecAlloc(T, size); CopyFrom(t);}
	SecBlock(const T *t, unsigned int size)
		: size(size) {ptr = SecAlloc(T, size); memcpy(ptr, t, size*sizeof(T));}
	~SecBlock()
		{SecFree(ptr, size);}

#if defined(__GNUC__) || defined(__BCPLUSPLUS__)
	operator const void *() const
		{return ptr;}
	operator void *()
		{return ptr;}
#endif

	operator const T *() const
		{return ptr;}
	operator T *()
		{return ptr;}

// CodeWarrior defines _MSC_VER
#if !defined(_MSC_VER) || defined(__MWERKS__)
	T *operator +(unsigned int offset)
		{return ptr+offset;}
	const T *operator +(unsigned int offset) const
		{return ptr+offset;}
	T& operator[](unsigned int index)
		{assert(index<size); return ptr[index];}
	const T& operator[](unsigned int index) const
		{assert(index<size); return ptr[index];}
#endif

	const T* Begin() const
		{return ptr;}
	T* Begin()
		{return ptr;}
	const T* End() const
		{return ptr+size;}
	T* End()
		{return ptr+size;}

	void CopyFrom(const SecBlock<T> &t)
	{
		New(t.size);
		memcpy(ptr, t.ptr, size*sizeof(T));
	}

	SecBlock& operator=(const SecBlock<T> &t)
	{
		CopyFrom(t);
		return *this;
	}

	bool operator==(const SecBlock<T> &t) const
	{
		return size == t.size && memcmp(ptr, t.ptr, size*sizeof(T)) == 0;
	}

	void New(unsigned int newSize)
	{
		if (newSize != size)
		{
			T *newPtr = SecAlloc(T, newSize);
			SecFree(ptr, size);
			ptr = newPtr;
			size = newSize;
		}
	}

	void CleanNew(unsigned int newSize)
	{
		if (newSize != size)
		{
			T *newPtr = SecAlloc(T, newSize);
			SecFree(ptr, size);
			ptr = newPtr;
			size = newSize;
		}
		memset(ptr, 0, size*sizeof(T));
	}

	void Grow(unsigned int newSize)
	{
		if (newSize > size)
		{
			T *newPtr = SecAlloc(T, newSize);
			memcpy(newPtr, ptr, size*sizeof(T));
			SecFree(ptr, size);
			ptr = newPtr;
			size = newSize;
		}
	}

	void CleanGrow(unsigned int newSize)
	{
		if (newSize > size)
		{
			T *newPtr = SecAlloc(T, newSize);
			memcpy(newPtr, ptr, size*sizeof(T));
			memset(newPtr+size, 0, (newSize-size)*sizeof(T));
			SecFree(ptr, size);
			ptr = newPtr;
			size = newSize;
		}
	}

	void Resize(unsigned int newSize)
	{
		if (newSize != size)
		{
			T *newPtr = SecAlloc(T, newSize);
			memcpy(newPtr, ptr, STDMIN(newSize, size)*sizeof(T));
			SecFree(ptr, size);
			ptr = newPtr;
			size = newSize;
		}
	}

	void swap(SecBlock<T> &b);

	unsigned int size;
	T *ptr;
};

template <class T> void SecBlock<T>::swap(SecBlock<T> &b)
{
	std::swap(size, b.size);
	std::swap(ptr, b.ptr);
}

typedef SecBlock<byte> SecByteBlock;
typedef SecBlock<word> SecWordBlock;

NAMESPACE_END

NAMESPACE_BEGIN(std)
template <class T>
inline void swap(CryptoPP::SecBlock<T> &a, CryptoPP::SecBlock<T> &b)
{
	a.swap(b);
}
NAMESPACE_END

#endif // MISC_H
