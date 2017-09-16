// gzip.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "gzip.h"

NAMESPACE_BEGIN(CryptoPP)

Gzip::Gzip(int dlevel, BufferedTransformation *bt)
	: Deflator(dlevel, bt),
	  m_totalLen(0)
{
	assert (dlevel >= 1 && dlevel <= 9);
	AttachedTransformation()->Put(MAGIC1);
	AttachedTransformation()->Put(MAGIC2);
	AttachedTransformation()->Put(DEFLATED);
	AttachedTransformation()->Put(0);		// general flag
	AttachedTransformation()->PutLong(0);	// time stamp
	byte extra = (dlevel == 1) ? FAST : ((dlevel == 9) ? SLOW : 0);
	AttachedTransformation()->Put(extra);
	AttachedTransformation()->Put(GZIP_OS_CODE);
}

void Gzip::Put(byte inByte)
{
	Deflator::Put(inByte);
	m_crc.Update(&inByte, 1);
	++m_totalLen;
}

void Gzip::Put(const byte *inString, unsigned int length)
{
	Deflator::Put(inString, length);
	m_crc.Update(inString, length);
	m_totalLen += length;
}

void Gzip::InputFinished()
{
	Deflator::InputFinished();
	SecByteBlock crc(4);
	m_crc.Final(crc);
	AttachedTransformation()->Put(crc, 4);
	AttachedTransformation()->PutLong(m_totalLen, false);
}

Gunzip::Gunzip(BufferedTransformation *output,
			   BufferedTransformation *bypassed)
	: Fork(output, bypassed), m_tail(8)
{
	m_inflator.SelectOutPort(1);
	m_inflator.Attach(new TailProcesser(*this));
	m_inflator.SelectOutPort(0);
	m_inflator.Attach(new BodyProcesser(*this));

	m_state = PROCESS_HEADER;
	m_tailLen = 0;
}

void Gunzip::Put(const byte *inString, unsigned int length)
{
	switch (m_state)
	{
		case PROCESS_HEADER:
			m_inQueue.Put(inString, length);
			if (m_inQueue.CurrentSize()>=MAX_HEADERSIZE)
				ProcessHeader();
			break;
		case PROCESS_BODY:
			m_inflator.Put(inString, length);
			break;
		case AFTER_END:
			AccessPort(1).Put(inString, length);
			break;
	}
}

void Gunzip::InputFinished()
{
	if (m_state==PROCESS_HEADER)
		ProcessHeader();

	if (m_state!=AFTER_END)
		m_inflator.InputFinished();
}

void Gunzip::ProcessHeader()
{
	byte buf[6];
	byte b, flags;

	if (m_inQueue.Get(buf, 2)!=2) goto error;
	if (buf[0] != MAGIC1 || buf[1] != MAGIC2) goto error;
	if (!m_inQueue.Skip(1)) goto error;	 // skip extra flags
	if (!m_inQueue.Get(flags)) goto error;
	if (flags & (ENCRYPTED | CONTINUED)) goto error;
	if (m_inQueue.Skip(6)!=6) goto error;    // Skip file time, extra flags and OS type

	if (flags & EXTRA_FIELDS)	// skip extra fields
	{
		word16 length;
		if(!m_inQueue.GetShort(length, false)) goto error;
		if (m_inQueue.Skip(length)!=length) goto error;
	}

	if (flags & FILENAME)	// skip filename
		do
			if(!m_inQueue.Get(b)) goto error;
		while (b);

	if (flags & COMMENTS)	// skip comments
		do
			if(!m_inQueue.Get(b)) goto error;
		while (b);

	m_inQueue.TransferTo(m_inflator);
	m_state = PROCESS_BODY;
	return;
error:
	throw HeaderErr();
}

void Gunzip::ProcessTail()
{
	assert(m_tailLen == 8);

	if (!m_crc.Verify(m_tail))
		throw CrcErr();

	if ((((word32)m_tail[4]) | ((word32)m_tail[5] << 8) | ((word32)m_tail[6] << 16) | ((word32)m_tail[7] << 24)) != m_totalLen)
		throw LengthErr();

	m_tailLen = 9;	// signal TailProcesser to bypass everything from now on
}

Gunzip::BodyProcesser::BodyProcesser(Gunzip &parent)
	: parent(parent)
{
	parent.m_totalLen = 0;
}

void Gunzip::BodyProcesser::Put(const byte *inString, unsigned int length)
{
	parent.AccessPort(0).Put(inString, length);
	parent.m_crc.Update(inString, length);
	parent.m_totalLen += length;
}

Gunzip::TailProcesser::TailProcesser(Gunzip &parent)
	: parent(parent)
{
	parent.m_tailLen = 0;
}

void Gunzip::TailProcesser::Put(const byte *inString, unsigned int length)
{
	if (parent.m_tailLen < 8)
	{
		int l = STDMIN(8-parent.m_tailLen, length);
		memcpy(parent.m_tail+parent.m_tailLen, inString, l);
		inString += l;
		length -= l;
		parent.m_tailLen += l;
	}

	if (parent.m_tailLen == 8)
		parent.ProcessTail();

	if (length)
		parent.AccessPort(1).Put(inString, length);
}

NAMESPACE_END
