// filters.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "filters.h"
#include "queue.h"
#include <memory>

NAMESPACE_BEGIN(CryptoPP)

Filter::Filter(BufferedTransformation *outQ)
	: m_outQueue(outQ ? outQ : new ByteQueue) 
{
}

void Filter::Detach(BufferedTransformation *newOut)
{
	std::auto_ptr<BufferedTransformation> out(newOut ? newOut : new ByteQueue);
	m_outQueue->Close();
	m_outQueue->TransferTo(*out);
	m_outQueue.reset(out.release());
}

void Filter::Attach(BufferedTransformation *newOut)
{
	if (m_outQueue->Attachable())
		m_outQueue->Attach(newOut);
	else
		Detach(newOut);
}

void Filter::Insert(Filter *filter)
{
	filter->m_outQueue.reset(m_outQueue.release());
	m_outQueue.reset(filter);
}

// *************************************************************

FilterWithBufferedInput::BlockQueue::BlockQueue(unsigned int blockSize, unsigned int maxBlocks)
	: m_buffer(blockSize * maxBlocks)
{
	ResetQueue(blockSize, maxBlocks);
}

void FilterWithBufferedInput::BlockQueue::ResetQueue(unsigned int blockSize, unsigned int maxBlocks)
{
	m_buffer.Resize(blockSize * maxBlocks);
	m_blockSize = blockSize;
	m_maxBlocks = maxBlocks;
	m_size = 0;
	m_begin = m_buffer;
}

const byte *FilterWithBufferedInput::BlockQueue::GetBlock()
{
	if (m_size >= m_blockSize)
	{
		const byte *ptr = m_begin;
		if ((m_begin+=m_blockSize) == m_buffer.End())
			m_begin = m_buffer;
		m_size -= m_blockSize;
		return ptr;
	}
	else
		return NULL;
}

const byte *FilterWithBufferedInput::BlockQueue::GetContigousBlocks(unsigned int &numberOfBlocks)
{
	numberOfBlocks = STDMIN(numberOfBlocks, STDMIN((unsigned int)(m_buffer.End()-m_begin), m_size)/m_blockSize);
	const byte *ptr = m_begin;
	if ((m_begin+=m_blockSize*numberOfBlocks) == m_buffer.End())
		m_begin = m_buffer;
	m_size -= m_blockSize*numberOfBlocks;
	return ptr;
}

unsigned int FilterWithBufferedInput::BlockQueue::GetAll(byte *outString)
{
	unsigned int size = m_size;
	unsigned int numberOfBlocks = m_maxBlocks;
	const byte *ptr = GetContigousBlocks(numberOfBlocks);
	memcpy(outString, ptr, numberOfBlocks*m_blockSize);
	memcpy(outString+numberOfBlocks*m_blockSize, m_begin, m_size);
	m_size = 0;
	return size;
}

void FilterWithBufferedInput::BlockQueue::Put(const byte *inString, unsigned int length)
{
	assert(m_size + length <= m_buffer.size);
	byte *end = (m_size < m_buffer+m_buffer.size-m_begin) ? m_begin + m_size : m_begin + m_size - m_buffer.size;
	unsigned int len = STDMIN(length, (unsigned int)(m_buffer+m_buffer.size-end));
	memcpy(end, inString, len);
	if (len < length)
		memcpy(m_buffer, inString+len, length-len);
	m_size += length;
}

FilterWithBufferedInput::FilterWithBufferedInput(unsigned int firstSize, unsigned int blockSize, unsigned int lastSize, BufferedTransformation *outQ)
	: Filter(outQ), m_firstSize(firstSize), m_blockSize(blockSize), m_lastSize(lastSize)
	, m_firstInputDone(firstSize == 0)
	, m_queue(m_firstInputDone ? m_blockSize : 1, m_firstInputDone ? (2*m_blockSize+m_lastSize-2)/m_blockSize : m_firstSize)
{
}

void FilterWithBufferedInput::Put(byte inByte)
{
	Put(&inByte, 1);
}

void FilterWithBufferedInput::Put(const byte *inString, unsigned int length)
{
	unsigned int newLength = m_queue.CurrentSize() + length;

	if (!m_firstInputDone && newLength >= m_firstSize)
	{
		unsigned int len = m_firstSize - m_queue.CurrentSize();
		m_queue.Put(inString, len);
		FirstPut(m_queue.GetContigousBlocks(m_firstSize));
		assert(m_queue.CurrentSize() == 0);
		m_queue.ResetQueue(m_blockSize, (2*m_blockSize+m_lastSize-2)/m_blockSize);

		inString += len;
		newLength -= m_firstSize;
		m_firstInputDone = true;
	}

	if (m_firstInputDone)
	{
		if (m_blockSize == 1)
		{
			while (newLength > m_lastSize && m_queue.CurrentSize() > 0)
			{
				unsigned int len = newLength - m_lastSize;
				const byte *ptr = m_queue.GetContigousBlocks(len);
				NextPut(ptr, len);
				newLength -= len;
			}

			if (newLength > m_lastSize)
			{
				unsigned int len = newLength - m_lastSize;
				NextPut(inString, len);
				inString += len;
				newLength -= len;
			}
		}
		else
		{
			while (newLength >= m_blockSize + m_lastSize && m_queue.CurrentSize() >= m_blockSize)
			{
				NextPut(m_queue.GetBlock(), m_blockSize);
				newLength -= m_blockSize;
			}

			if (newLength >= m_blockSize + m_lastSize && m_queue.CurrentSize() > 0)
			{
				assert(m_queue.CurrentSize() < m_blockSize);
				unsigned int len = m_blockSize - m_queue.CurrentSize();
				m_queue.Put(inString, len);
				inString += len;
				NextPut(m_queue.GetBlock(), m_blockSize);
				newLength -= m_blockSize;
			}

			while (newLength >= m_blockSize + m_lastSize)
			{
				NextPut(inString, m_blockSize);
				inString += m_blockSize;
				newLength -= m_blockSize;
			}
		}
	}

	m_queue.Put(inString, newLength - m_queue.CurrentSize());
}

void FilterWithBufferedInput::InputFinished()
{
	SecByteBlock temp(m_queue.CurrentSize());
	m_queue.GetAll(temp);
	LastPut(temp, temp.size);
}

void FilterWithBufferedInput::ForceNextPut()
{
	if (m_firstInputDone && m_queue.CurrentSize() >= m_blockSize)
		NextPut(m_queue.GetBlock(), m_blockSize);
}

// *************************************************************

void StreamCipherFilter::Put(const byte *inString, unsigned int length)
{
	SecByteBlock temp(length);
	cipher.ProcessString(temp, inString, length);
	AttachedTransformation()->Put(temp, length);
}

void HashFilter::InputFinished()
{
	SecByteBlock buf(hash.DigestSize());
	hash.Final(buf);
	AttachedTransformation()->Put(buf, buf.size);
}

void HashComparisonFilter::PutHash(const byte *eh)
{
	memcpy(expectedHash, eh, expectedHash.size);
}

void HashComparisonFilter::InputFinished()
{
	AttachedTransformation()->Put(hash.Verify(expectedHash));
}

void SignerFilter::InputFinished()
{
	SecByteBlock buf(signer.SignatureLength());
	signer.Sign(rng, messageAccumulator.release(), buf);
	AttachedTransformation()->Put(buf, buf.size);
}

void VerifierFilter::PutSignature(const byte *sig)
{
	memcpy(signature.ptr, sig, signature.size);
}

void VerifierFilter::InputFinished()
{
	AttachedTransformation()->Put((byte)verifier.Verify(messageAccumulator.release(), signature));
}

StringSource::StringSource(const char *source, bool pumpAndClose, BufferedTransformation *outQueue)
	: Source(outQueue), m_source((const byte *)source), m_length(strlen(source)), m_count(0)
{
	if (pumpAndClose)
	{
		PumpAll();
		Close();
	}
}

StringSource::StringSource(const byte *source, unsigned int length, bool pumpAndClose, BufferedTransformation *outQueue)
	: Source(outQueue), m_source(source), m_length(length), m_count(0)
{
	if (pumpAndClose)
	{
		PumpAll();
		Close();
	}
}

StringSource::StringSource(const std::string &source, bool pumpAndClose, BufferedTransformation *outQueue)
	: Source(outQueue), m_source((byte *)source.data()), m_length(source.length()), m_count(0)
{
	if (pumpAndClose)
	{
		PumpAll();
		Close();
	}
}

unsigned int StringSource::Pump(unsigned int pumpMax)
{
	pumpMax = STDMIN(pumpMax, m_length-m_count);
	AttachedTransformation()->Put(m_source, pumpMax);
	m_count += pumpMax;
	return pumpMax;
}

unsigned long StringSource::PumpAll()
{
	return Pump(m_length-m_count);
}

unsigned long StringStore::MaxRetrieveable()
{
	return m_length - m_count;
}

unsigned int StringStore::Get(byte &outByte)
{
	unsigned int len = Peek(outByte);
	m_count += len;
	return len;
}

unsigned int StringStore::Get(byte *outString, unsigned int getMax)
{
	unsigned int len = Peek(outString, getMax);
	m_count += len;
	return len;
}

unsigned int StringStore::Peek(byte &outByte) const
{
	if (m_count < m_length)
	{
		outByte = m_store[m_count];
		return 1;
	}
	else
		return 0;
}

unsigned int StringStore::Peek(byte *outString, unsigned int peekMax) const
{
	peekMax = STDMIN(peekMax, m_length-m_count);
	memcpy(outString, m_store+m_count, peekMax);
	return peekMax;
}

unsigned long StringStore::CopyTo(BufferedTransformation &target) const
{
	unsigned len = m_length-m_count;
	target.Put(m_store+m_count, len);
	return len;
}

unsigned int StringStore::CopyTo(BufferedTransformation &target, unsigned int copyMax) const
{
	unsigned len = STDMIN(m_length-m_count, copyMax);
	target.Put(m_store+m_count, len);
	return len;
}

BufferedTransformation *Insert(const byte *in, unsigned int length, BufferedTransformation *outQueue)
{
	outQueue->Put(in, length);
	return outQueue;
}

unsigned int Extract(Source *source, byte *out, unsigned int length)
{
	while (source->MaxRetrieveable() < length && source->Pump(1));
	return source->Get(out, length);
}

NAMESPACE_END
