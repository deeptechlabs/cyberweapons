#ifndef CRYPTOPP_SECSHARE_H
#define CRYPTOPP_SECSHARE_H

#include "forkjoin.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

class ShareFork : public Fork
{
public:
	// fork into n shares, with m necessary to reconstruct
	ShareFork(RandomNumberGenerator &rng, word32 m, word32 n,
			  BufferedTransformation *const *outports = NULL);

	void Put(byte inByte);
	void Put(const byte *inString, unsigned int length);
	virtual void InputFinished();

protected:
	void Process(unsigned int message);
	virtual void Share(word32 message);

	RandomNumberGenerator &m_rng;
	word32 m_threshold;
	word32 m_buffer;
	unsigned int m_count;
};

class ShareJoin : public Join
{
public:
	ShareJoin(unsigned int n, BufferedTransformation *outQ = NULL);

	void NotifyInput(unsigned int interfaceId, unsigned int length);

protected:
	void ReadIndex();
	virtual void Assemble(unsigned long);
	void Output(word32);
	void NotifyClose(unsigned int);

	word32 m_threshold;
	SecBlock<word32> m_x;
	word32 m_buffer;
	bool m_indexRead, m_firstOutput;
};

class DisperseFork : public ShareFork
{
public:
	DisperseFork(unsigned int m, unsigned int n, BufferedTransformation *const *outports = NULL);

	virtual void InputFinished();

protected:
	virtual void Share(word32 message);

	SecBlock<word32> m_poly;
	unsigned int m_polyCount;
};

class DisperseJoin : public ShareJoin
{
public:
	DisperseJoin(unsigned int n, BufferedTransformation *outQ = NULL);

	void NotifyClose(unsigned int id);

protected:
	virtual void Assemble(unsigned long);

	SecBlock<word32> m_polyBuffer;
	bool m_firstPolyOutput;
};

NAMESPACE_END

#endif
