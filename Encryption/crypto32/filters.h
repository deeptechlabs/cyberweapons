#ifndef CRYPTOPP_FILTERS_H
#define CRYPTOPP_FILTERS_H

#include "cryptlib.h"
#include "misc.h"
#include "smartptr.h"

NAMESPACE_BEGIN(CryptoPP)

// Filter provides an implementation of BufferedTransformation's
// attachment interface

class Filter : public BufferedTransformation
{
public:
	Filter(BufferedTransformation *outQ);

	bool Attachable() {return true;}
	BufferedTransformation *AttachedTransformation() {return m_outQueue.get();}
	const BufferedTransformation *AttachedTransformation() const {return m_outQueue.get();}
	void Detach(BufferedTransformation *newOut = NULL);
	void Attach(BufferedTransformation *newOut);
	void Close()
		{InputFinished(); m_outQueue->Close();}

	unsigned long MaxRetrieveable()
		{return m_outQueue->MaxRetrieveable();}

	unsigned int Get(byte &outByte)
		{return m_outQueue->Get(outByte);}
	unsigned int Get(byte *outString, unsigned int getMax)
		{return m_outQueue->Get(outString, getMax);}

	unsigned long TransferTo(BufferedTransformation &target)
		{return m_outQueue->TransferTo(target);}
	unsigned int TransferTo(BufferedTransformation &target, unsigned int transferMax)
		{return m_outQueue->TransferTo(target, transferMax);}

	unsigned int Peek(byte &outByte) const
		{return m_outQueue->Peek(outByte);}
	unsigned int Peek(byte *outString, unsigned int peekMax) const
		{return m_outQueue->Peek(outString, peekMax);}

	unsigned long CopyTo(BufferedTransformation &target) const
		{return m_outQueue->CopyTo(target);}
	unsigned int CopyTo(BufferedTransformation &target, unsigned int copyMax) const
		{return m_outQueue->CopyTo(target, copyMax);}

protected:
	void Insert(Filter *nextFilter);	// insert filter after this one

private:
	void operator=(const Filter &); // assignment not allowed

	member_ptr<BufferedTransformation> m_outQueue;
};

// FilterWithBufferedInput divides up the input stream into
// a first block, a number of middle blocks, and a last block.
// First and last blocks are optional, and middle blocks may
// be a stream instead (i.e. blockSize == 1).

class FilterWithBufferedInput : public Filter
{
public:
	// firstSize and lastSize may be 0, blockSize must be at least 1
	FilterWithBufferedInput(unsigned int firstSize, unsigned int blockSize, unsigned int lastSize, BufferedTransformation *outQ);
	void Put(byte inByte);
	void Put(const byte *inString, unsigned int length);
	void InputFinished();

	// the input buffer may contain more than blockSize bytes if lastSize != 0
	// ForceNextPut() forces a call to NextPut() if this is the case
	void ForceNextPut();

protected:
	bool DidFirstPut() {return m_firstSize != 0 && m_firstInputDone;}

	// FirstPut() is called if firstSize != 0 and totalLength >= firstSize
	virtual void FirstPut(const byte *inString) {assert(false);}
	// NextPut() is called if totalLength >= firstSize+blockSize+lastSize
	// length parameter is always blockSize unless blockSize == 1
	virtual void NextPut(const byte *inString, unsigned int length) =0;
	// LastPut() is always called
	// if totalLength < firstSize then length == totalLength
	// else if totalLength <= firstSize+lastSize then length == totalLength-firstSize
	// else lastSize <= length < lastSize+blockSize
	virtual void LastPut(const byte *inString, unsigned int length) =0;

private:
	class BlockQueue
	{
	public:
		BlockQueue(unsigned int blockSize, unsigned int maxBlocks);
		void ResetQueue(unsigned int blockSize, unsigned int maxBlocks);
		const byte *GetBlock();
		const byte *GetContigousBlocks(unsigned int &numberOfBlocks);
		unsigned int GetAll(byte *outString);
		void Put(const byte *inString, unsigned int length);
		unsigned int CurrentSize() const {return m_size;}
		unsigned int MaxSize() const {return m_buffer.size;}

	private:
		SecByteBlock m_buffer;
		unsigned int m_blockSize, m_maxBlocks, m_size;
		byte *m_begin;
	};

	unsigned int m_firstSize, m_blockSize, m_lastSize;
	bool m_firstInputDone;
	BlockQueue m_queue;
};

class StreamCipherFilter : public Filter
{
public:
	StreamCipherFilter(StreamCipher &c,
					   BufferedTransformation *outQueue = NULL)
		: cipher(c), Filter(outQueue) {}

	void Put(byte inByte)
		{AttachedTransformation()->Put(cipher.ProcessByte(inByte));}

	void Put(const byte *inString, unsigned int length);

private:
	StreamCipher &cipher;
};

class HashFilter : public Filter
{
public:
	HashFilter(HashModule &hm, BufferedTransformation *outQueue = NULL)
		: hash(hm), Filter(outQueue) {}

	void InputFinished();

	void Put(byte inByte)
		{hash.Update(&inByte, 1);}

	void Put(const byte *inString, unsigned int length)
		{hash.Update(inString, length);}

private:
	HashModule &hash;
};

class HashComparisonFilter : public Filter
{
public:
	HashComparisonFilter(HashModule &hm, BufferedTransformation *outQueue = NULL)
		: hash(hm), expectedHash(hm.DigestSize()), Filter(outQueue) {}

	// this function must be called before InputFinished() or Close()
	void PutHash(const byte *expectedHash);

	void InputFinished();

	void Put(byte inByte)
		{hash.Update(&inByte, 1);}

	void Put(const byte *inString, unsigned int length)
		{hash.Update(inString, length);}

private:
	HashModule &hash;
	SecByteBlock expectedHash;
};

class SignerFilter : public Filter
{
public:
	SignerFilter(RandomNumberGenerator &rng, const PK_Signer &signer, BufferedTransformation *outQueue = NULL)
		: rng(rng), signer(signer), messageAccumulator(signer.NewMessageAccumulator()), Filter(outQueue) {}

	void InputFinished();

	void Put(byte inByte)
		{messageAccumulator->Update(&inByte, 1);}

	void Put(const byte *inString, unsigned int length)
		{messageAccumulator->Update(inString, length);}

private:
	RandomNumberGenerator &rng;
	const PK_Signer &signer;
	member_ptr<HashModule> messageAccumulator;
};

class VerifierFilter : public Filter
{
public:
	VerifierFilter(const PK_Verifier &verifier, BufferedTransformation *outQueue = NULL)
		: verifier(verifier), messageAccumulator(verifier.NewMessageAccumulator())
		, signature(verifier.SignatureLength()), Filter(outQueue) {}

	// this function must be called before InputFinished() or Close()
	void PutSignature(const byte *sig);

	void InputFinished();

	void Put(byte inByte)
		{messageAccumulator->Update(&inByte, 1);}

	void Put(const byte *inString, unsigned int length)
		{messageAccumulator->Update(inString, length);}

private:
	const PK_Verifier &verifier;
	member_ptr<HashModule> messageAccumulator;
	SecByteBlock signature;
};

class Source : public Filter
{
public:
	Source(BufferedTransformation *outQ)
		: Filter(outQ) {}

	void Put(byte)
		{Pump(1);}
	void Put(const byte *, unsigned int length)
		{Pump(length);}
	void InputFinished()
		{PumpAll();}

	virtual unsigned int Pump(unsigned int pumpMax) =0;
	virtual unsigned long PumpAll() =0;
};

class StringSource : public Source
{
public:
	StringSource(const char *source, bool pumpAndClose, BufferedTransformation *outQueue = NULL);
	StringSource(const byte *source, unsigned int length, bool pumpAndClose, BufferedTransformation *outQueue = NULL);
	StringSource(const std::string &source, bool pumpAndClose, BufferedTransformation *outQueue = NULL);

	unsigned int Pump(unsigned int size);
	unsigned long PumpAll();

private:
	const byte *m_source;
	unsigned int m_length, m_count;
};

class Sink : public BufferedTransformation
{
public:
	unsigned long MaxRetrieveable()
		{return 0;}
	unsigned int Get(byte &)
		{return 0;}
	unsigned int Get(byte *, unsigned int)
		{return 0;}
	unsigned int Peek(byte &) const
		{return 0;}
	unsigned int Peek(byte *outString, unsigned int peekMax) const
		{return 0;}
	unsigned long CopyTo(BufferedTransformation &target) const
		{return 0;}
	unsigned int CopyTo(BufferedTransformation &target, unsigned int copyMax) const
		{return 0;}
};

class BitBucket : public Sink
{
public:
	void Put(byte) {}
	void Put(const byte *, unsigned int) {}
};

class StringSink : public Sink
{
public:
	StringSink(std::string &output)
		: m_output(output) {}
	void Put(byte b)
		{m_output += b;}
	void Put(const byte *str, unsigned int bc)
		{m_output.append((const char *)str, bc);}

private:	
	std::string &m_output;
};

class Store : public BufferedTransformation
{
public:
	void Put(byte)
		{}
	void Put(const byte *, unsigned int length)
		{}
	void InputFinished()
		{}
};

class StringStore : public Store
{
public:
	StringStore(const char *store)
		: m_store((const byte *)store), m_length(strlen(store)), m_count(0) {}
	StringStore(const byte *store, unsigned int length)
		: m_store(store), m_length(length), m_count(0) {}

	unsigned long MaxRetrieveable();

	unsigned int Get(byte &outByte);
	unsigned int Get(byte *outString, unsigned int getMax);

	unsigned int Peek(byte &outByte) const;
	unsigned int Peek(byte *outString, unsigned int peekMax) const;

	unsigned long CopyTo(BufferedTransformation &target) const;
	unsigned int CopyTo(BufferedTransformation &target, unsigned int copyMax) const;

private:
	const byte *m_store;
	unsigned int m_length, m_count;
};

BufferedTransformation *Insert(const byte *in, unsigned int length, BufferedTransformation *outQueue);
unsigned int Extract(Source *source, byte *out, unsigned int length);

NAMESPACE_END

#endif
