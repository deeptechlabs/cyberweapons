// asn.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "asn.h"

#include <strstream>
#include <iomanip>
#include <time.h>

NAMESPACE_BEGIN(CryptoPP)
USING_NAMESPACE(std)

/// DER Length
unsigned int DERLengthEncode(unsigned int length, byte *output)
{
	unsigned int i=0;
	if (output)
	{
		if (length <= 0x7f)
		{
			output[i++] = byte(length);
		}
		else
		{
			output[i++] = byte(BytePrecision(length) | 0x80);
			for (int j=BytePrecision(length); j; --j)
			{
				output[i++] = byte (length >> (j-1)*8);
			}
		}
	}
	else
	{
		if (length <= 0x7f)
			i++;
		else
		{
			i++;
			for (int j=BytePrecision(length); j; --j)
				i++;
		}
	}
	return i;
}

unsigned int DERLengthEncode(unsigned int length, BufferedTransformation &bt)
{
	byte buf[10];	// should be more than enough
	unsigned int i = DERLengthEncode(length, buf);
	assert(i <= 10);
	bt.Put(buf, i);
	return i;
}

bool BERLengthDecode(BufferedTransformation &bt, unsigned int &length)
{
	byte b;

	if (!bt.Get(b))
		BERDecodeError();

	if (!(b & 0x80))
		length = b;
	else
	{
		unsigned int lengthBytes = b & 0x7f;

		if (lengthBytes == 0)
			return false;	// indefinite length

		length = 0;
		while (lengthBytes--)
		{
			if (length >> (8*(sizeof(length)-1)))
				BERDecodeError();	// length about to overflow

			if (!bt.Get(b))
				BERDecodeError();

			length = (length << 8) | b;
		}
	}
	return true;
}

unsigned int BERExtractDefiniteLengthField(BufferedTransformation &input, BufferedTransformation &output)
{
	unsigned int bc;
	byte tag;
	if (!input.Get(tag))
		BERDecodeError();
	output.Put(tag);
	if (!BERLengthDecode(input, bc))
		BERDecodeError();
	DERLengthEncode(bc, output);
	if (input.TransferTo(output, bc) != bc)
		BERDecodeError();
	return bc;
}

/// ASN Strings
unsigned int DEREncodeOctetString(const byte *str, unsigned int strLen, BufferedTransformation &bt)
{
	bt.Put(OCTET_STRING);
	unsigned int lengthBytes = DERLengthEncode(strLen, bt);
	bt.Put(str, strLen);
	return 1+lengthBytes+strLen;
}

unsigned int DEREncodeOctetString(const SecByteBlock &str, BufferedTransformation &bt)
{
	return DEREncodeOctetString(str.ptr, str.size, bt);
}

unsigned int BERDecodeOctetString(BufferedTransformation &bt, SecByteBlock &str)
{
	byte b;
	if (!bt.Get(b) || b != OCTET_STRING)
		BERDecodeError();

	unsigned int bc;
	BERLengthDecode(bt, bc);

	str.Resize(bc);
	if (bc != bt.Get(str, bc))
		BERDecodeError();
	return bc;
}

unsigned int DEREncodeTextString(const std::string &str, BufferedTransformation &bt, byte asnTag)
{
	bt.Put(asnTag);
	unsigned int lengthBytes = DERLengthEncode(str.size(), bt);
	bt.Put((const byte *)str.data(), str.size());
	return 1+lengthBytes+str.size();
}

unsigned int BERDecodeTextString(BufferedTransformation &bt, std::string &str, byte asnTag)
{
	byte b;
	if (!bt.Get(b) || b != asnTag)
		BERDecodeError();

	unsigned int bc;
	BERLengthDecode(bt, bc);

	SecByteBlock temp(bc);
	if (bc != bt.Get(temp, bc))
		BERDecodeError();
	str.assign((char *)temp.ptr, bc);
	return bc;
}

/// ASN BitString
unsigned int DEREncodeBitString(const byte *str, unsigned int strLen, BufferedTransformation &bt)
{
	bt.Put(BIT_STRING);
	unsigned int lengthBytes = DERLengthEncode(strLen+1, bt);
	bt.Put((byte)0);
	bt.Put(str, strLen);
	return 1+lengthBytes+strLen;
}

unsigned int BERDecodeBitString(BufferedTransformation &bt, SecByteBlock &str)
{
	byte b;
	if (!bt.Get(b) || b != BIT_STRING)
		BERDecodeError();

	unsigned int bc;
	BERLengthDecode(bt, bc);

	byte unused;
	if (!bt.Get(unused) || unused != 0)
		BERDecodeError();
	str.Resize(bc-1);
	if ((bc-1) != bt.Get(str, bc-1))
		BERDecodeError();
	return bc;
}

/// ASN Sequence
BERSequenceDecoder::BERSequenceDecoder(BufferedTransformation &inQueue, byte asnTag)
	: m_inQueue(inQueue), m_finished(false)
{
	byte b;
	if (!m_inQueue.Get(b) || b != asnTag)
		BERDecodeError();

	m_definiteLength = BERLengthDecode(m_inQueue, m_length);
}

BERSequenceDecoder::BERSequenceDecoder(BERSequenceDecoder &inQueue, byte asnTag)
	: m_inQueue(inQueue), m_finished(false)
{
	byte b;
	if (!m_inQueue.Get(b) || b != asnTag)
		BERDecodeError();

	m_definiteLength = BERLengthDecode(m_inQueue, m_length);
}

BERSequenceDecoder::~BERSequenceDecoder()
{
	try	// avoid throwing in constructor
	{
		OutputFinished();
	}
	catch (...)
	{
	}
}

void BERSequenceDecoder::OutputFinished()
{
	if (m_finished)
		return;
	else
		m_finished = true;

	if (!m_definiteLength)
	{	// remove end-of-content Octets
		word16 i;
		if (!m_inQueue.GetShort(i) || (i!=0))
			BERDecodeError();
	}
}

unsigned long BERSequenceDecoder::MaxRetrieveable()
{
	unsigned long maxRet = m_inQueue.MaxRetrieveable();

	if (m_definiteLength)
		return STDMIN(maxRet, (unsigned long)m_length);
	else
		return maxRet;
}

unsigned int BERSequenceDecoder::Get(byte &outByte)
{
	if (!m_definiteLength || m_length >= 1)
		return ReduceLength(m_inQueue.Get(outByte));
	else
		return 0;
}

unsigned int BERSequenceDecoder::Get(byte *outString, unsigned int getMax)
{
	return ReduceLength(m_inQueue.Get(outString, m_definiteLength ? STDMIN(getMax, m_length) : getMax));
}

unsigned int BERSequenceDecoder::Peek(byte &outByte) const
{
	if (!m_definiteLength || m_length >= 1)
		return m_inQueue.Peek(outByte);
	else
		return 0;
}

unsigned int BERSequenceDecoder::Peek(byte *outString, unsigned int peekMax) const
{
	return m_inQueue.Peek(outString, m_definiteLength ? STDMIN(peekMax, m_length) : peekMax);
}

unsigned long BERSequenceDecoder::CopyTo(BufferedTransformation &target) const
{
	return m_inQueue.CopyTo(target, m_definiteLength ? m_length : m_inQueue.MaxRetrieveable());
}

unsigned int BERSequenceDecoder::CopyTo(BufferedTransformation &target, unsigned int copyMax) const
{
	return m_inQueue.CopyTo(target, m_definiteLength ? STDMIN(copyMax, m_length) : copyMax);
}

unsigned int BERSequenceDecoder::ReduceLength(unsigned int delta)
{
	if (m_definiteLength)
	{
		assert(m_length >= delta);
		m_length -= delta;
	}
	return delta;
}

DERSequenceEncoder::DERSequenceEncoder(BufferedTransformation &outQueue, byte asnTag)
	: m_outQueue(outQueue), m_asnTag(asnTag), m_finished(false)
{
}

DERSequenceEncoder::DERSequenceEncoder(DERSequenceEncoder &outQueue, byte asnTag)
	: m_outQueue(outQueue), m_asnTag(asnTag), m_finished(false)
{
}

DERSequenceEncoder::~DERSequenceEncoder()
{
	try	// avoid throwing in constructor
	{
		InputFinished();
	}
	catch (...)
	{
	}
}

void DERSequenceEncoder::InputFinished()
{
	if (m_finished)
		return;
	else
		m_finished = true;

	unsigned int length = (unsigned int)CurrentSize();
	m_outQueue.Put(m_asnTag);
	DERLengthEncode(length, m_outQueue);
	TransferTo(m_outQueue);
}

/// ASN Set
DERSetEncoder::DERSetEncoder(BufferedTransformation &outQueue, byte asnTag)
	: DERSequenceEncoder(outQueue, asnTag)
{
}

DERSetEncoder::DERSetEncoder(DERSetEncoder &outQueue, byte asnTag)
	: DERSequenceEncoder(outQueue, asnTag)
{
}

BERSetDecoder::BERSetDecoder(BufferedTransformation &inQueue, byte asnTag)
	: BERSequenceDecoder(inQueue, asnTag)
{
}

BERSetDecoder::BERSetDecoder(BERSetDecoder &inQueue, byte asnTag)
	: BERSequenceDecoder(inQueue, asnTag)
{
}


NAMESPACE_END
