#ifndef CRYPTOPP_ASN_H
#define CRYPTOPP_ASN_H

#include "cryptlib.h"
#include "queue.h"
#include "misc.h"

NAMESPACE_BEGIN(CryptoPP)

// NOTE: these tags and flags are NOT COMPLETE!
enum ASNTag
{
	BOOLEAN 			= 0x01,
	INTEGER 			= 0x02,
	BIT_STRING			= 0x03,
	OCTET_STRING		= 0x04,
	NULL_VALUE			= 0x05,
	OBJECT_IDENTIFIER	= 0x06,
	OBJECT_DESCRIPTOR	= 0x07,
	EXTERNAL			= 0x08,
	REAL				= 0x09,
	ENUMERATED			= 0x0a,
	UTF8_STRING			= 0x0c,
	SEQUENCE			= 0x10,
	SET 				= 0x11,
	NUMERIC_STRING		= 0x12,
	PRINTABLE_STRING 	= 0x13,
	T61_STRING			= 0x14,
	VIDEOTEXT_STRING 	= 0x15,
	IA5_STRING			= 0x16,
	UTC_TIME 			= 0x17,
	GENERALIZED_TIME 	= 0x18,
	GRAPHIC_STRING		= 0x19,
	VISIBLE_STRING		= 0x1a,
	GENERAL_STRING		= 0x1b,
};

enum ASNIdFlag
{
	UNIVERSAL			= 0x00,
	DATA				= 0x01,
	HEADER				= 0x02,
	CONSTRUCTED 		= 0x20,
	APPLICATION 		= 0x40,
	CONTEXT_SPECIFIC	= 0x80,
	PRIVATE 			= 0xc0,
};

#define BERDecodeError() throw BERDecodeErr()

class BERDecodeErr : public Exception
{
public: 
	BERDecodeErr() : Exception("BER decode error") {}
	BERDecodeErr(const char *err) : Exception(err) {}
};

unsigned int DERLengthEncode(unsigned int length, byte *output=0);
unsigned int DERLengthEncode(unsigned int length, BufferedTransformation &);
// returns false if indefinite length
bool BERLengthDecode(BufferedTransformation &, unsigned int &length);
unsigned int BERExtractDefiniteLengthField(BufferedTransformation &input, BufferedTransformation &output);

unsigned int DEREncodeOctetString(const byte *str, unsigned int strLen, BufferedTransformation &bt);
unsigned int DEREncodeOctetString(const SecByteBlock &str, BufferedTransformation &bt);
unsigned int BERDecodeOctetString(BufferedTransformation &bt, SecByteBlock &str);

// for UTF8_STRING, PRINTABLE_STRING, and IA5_STRING
unsigned int DEREncodeTextString(const std::string &str, BufferedTransformation &bt, byte asnTag);
unsigned int BERDecodeTextString(BufferedTransformation &bt, std::string &str, byte asnTag);

unsigned int DEREncodeBitString(const byte *str, unsigned int strLen, BufferedTransformation &bt);
unsigned int BERDecodeBitString(BufferedTransformation &bt, SecByteBlock &str);

class BERSequenceDecoder : public BufferedTransformation
{
public:
	BERSequenceDecoder(BufferedTransformation &inQueue, byte asnTag = SEQUENCE | CONSTRUCTED);
	BERSequenceDecoder(BERSequenceDecoder &inQueue, byte asnTag = SEQUENCE | CONSTRUCTED);
	~BERSequenceDecoder();

	bool IsDefiniteLength() const {return m_definiteLength;}
	unsigned int RemainingLength() const {assert(m_definiteLength); return m_length;}

	void Put(byte inByte) {}
	void Put(const byte *inString, unsigned int length) {}

	unsigned long MaxRetrieveable();

	unsigned int Get(byte &outByte);
	unsigned int Get(byte *outString, unsigned int getMax);

	unsigned int Peek(byte &outByte) const;
	unsigned int Peek(byte *outString, unsigned int peekMax) const;

	unsigned long CopyTo(BufferedTransformation &target) const;
	unsigned int CopyTo(BufferedTransformation &target, unsigned int copyMax) const;

	// call this to denote end of sequence
	void OutputFinished();

protected:
	BufferedTransformation &m_inQueue;
	bool m_finished, m_definiteLength;
	unsigned int m_length;

private:
	unsigned int ReduceLength(unsigned int delta);
};

class DERSequenceEncoder : public ByteQueue
{
public:
	DERSequenceEncoder(BufferedTransformation &outQueue, byte asnTag = SEQUENCE | CONSTRUCTED);
	DERSequenceEncoder(DERSequenceEncoder &outQueue, byte asnTag = SEQUENCE | CONSTRUCTED);
	~DERSequenceEncoder();

	// call this to denote end of sequence
	void InputFinished();

private:
	BufferedTransformation &m_outQueue;
	bool m_finished;

	byte m_asnTag;
};

class BERSetDecoder : public BERSequenceDecoder
{
public:
	BERSetDecoder(BufferedTransformation &inQueue, byte asnTag = SET | CONSTRUCTED);
	BERSetDecoder(BERSetDecoder &inQueue, byte asnTag = SET | CONSTRUCTED);
};

class DERSetEncoder : public DERSequenceEncoder
{
public:
	DERSetEncoder(BufferedTransformation &outQueue, byte asnTag = SET | CONSTRUCTED);
	DERSetEncoder(DERSetEncoder &outQueue, byte asnTag = SET | CONSTRUCTED);
};

// ********************************************************

// for INTEGER, BOOLEAN, and ENUM
template <class T>
unsigned int DEREncodeUnsigned(T w, BufferedTransformation &bt, byte asnTag = INTEGER)
{
	byte buf[sizeof(w)];
	for (unsigned int i=0; i<sizeof(w); i++)
		buf[i] = byte(w >> (sizeof(w)-1-i)*8);
	unsigned int bc = sizeof(w);
	while (bc > 1 && buf[sizeof(w)-bc] == 0)
		bc--;
	bt.Put(asnTag);
	unsigned int lengthBytes = DERLengthEncode(bc, bt);
	bt.Put(buf+sizeof(w)-bc, bc);
	return 1+lengthBytes+bc;
}

// VC60 workaround: std::numeric_limits<T>::max conflicts with MFC max macro
// CW41 workaround: std::numeric_limits<T>::max causes a template error
template <class T>
void BERDecodeUnsigned(BufferedTransformation &bt, T &w, byte asnTag = INTEGER,
					   T minValue = 0, T maxValue = 0xffffffff)
{
	byte b;
	if (!bt.Get(b) || b != asnTag)
		BERDecodeError();

	unsigned int bc;
	BERLengthDecode(bt, bc);

	SecByteBlock buf(bc);

	if (bc != bt.Get(buf, bc))
		BERDecodeError();

	const byte *ptr = buf;
	while (bc > sizeof(w) && *ptr == 0)
	{
		bc--;
		ptr++;
	}
	if (bc > sizeof(w))
		BERDecodeError();

	w = 0;
	for (unsigned int i=0; i<bc; i++)
		w = (w << 8) | ptr[i];

	if (w < minValue || w > maxValue)
		BERDecodeError();
}

NAMESPACE_END

#endif
