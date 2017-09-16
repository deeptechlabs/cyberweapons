#ifndef CRYPTOPP_GZIP_H
#define CRYPTOPP_GZIP_H

#include "zdeflate.h"
#include "zinflate.h"
#include "crc.h"

NAMESPACE_BEGIN(CryptoPP)

class Gzip : public Deflator
{
public:
	Gzip(int deflate_level, BufferedTransformation *bt = NULL);

	void Put(byte inByte);
	void Put(const byte *inString, unsigned int length);
	void InputFinished();

protected:
	enum {MAGIC1=0x1f, MAGIC2=0x8b,   // flags for the header
		  DEFLATED=8, FAST=4, SLOW=2};

	unsigned long m_totalLen;
	CRC32 m_crc;
};

class Gunzip : public Fork
{
public:
	class Err : public Exception {public: Err(const char *message) : Exception(message) {}};
	class HeaderErr : public Err {public: HeaderErr() : Err("Gunzip: header decoding error") {}};
	class CrcErr : public Err {public: CrcErr() : Err("Gunzip: CRC check error") {}};
	class LengthErr : public Err {public: LengthErr() : Err("Gunzip: length check error") {}};

	Gunzip(BufferedTransformation *output = NULL,
		   BufferedTransformation *bypassed = NULL);

	void Put(byte inByte) {Put(&inByte, 1);}
	void Put(const byte *inString, unsigned int length);
	void InputFinished();

protected:
	enum {MAGIC1=0x1f, MAGIC2=0x8b,   // flags for the header
		  DEFLATED=8,
		  MAX_HEADERSIZE=1024};

	enum FLAG_MASKS {
		CONTINUED=2, EXTRA_FIELDS=4, FILENAME=8, COMMENTS=16, ENCRYPTED=32};

	class BodyProcesser : public Sink
	{
	public:
		BodyProcesser(Gunzip &parent);
		void Put(byte inByte) {Put(&inByte, 1);}
		void Put(const byte *inString, unsigned int length);
	private:
		Gunzip &parent;
	};

	class TailProcesser : public Sink
	{
	public:
		TailProcesser(Gunzip &parent);
		void Put(byte inByte) {Put(&inByte, 1);}
		void Put(const byte *inString, unsigned int length);
	private:
		Gunzip &parent;
	};

	friend class BodyProcesser;
	friend class TailProcesser;

	void ProcessHeader();
	void ProcessTail();

	Inflator m_inflator;
	ByteQueue m_inQueue;

	unsigned long m_totalLen;
	CRC32 m_crc;

	SecByteBlock m_tail;
	unsigned int m_tailLen;

	enum State {PROCESS_HEADER, PROCESS_BODY, AFTER_END};
	State m_state;
};

NAMESPACE_END

#endif
