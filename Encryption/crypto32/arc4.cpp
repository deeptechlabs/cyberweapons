// arc2.cpp - this code comes from an anonymous Usenet post
// any modifications are placed in the public domain by Wei Dai

#include "pch.h"
#include "arc4.h"

NAMESPACE_BEGIN(CryptoPP)

ARC4::ARC4(const byte *key_data_ptr, unsigned int key_data_len)
    : m_state(256), m_x(0), m_y(0)
{
    unsigned int counter;
    for (counter = 0; counter < 256; counter++)
        m_state[counter] = (byte) counter;

    byte index1 = 0;
    byte index2 = 0;
    for (counter = 0; counter < 256; counter++)
	{
        index2 = (key_data_ptr[index1++] + m_state[counter] + index2);
		std::swap(m_state[counter], m_state[index2]);
		if (index1 >= key_data_len) index1 = 0;
    }
}

ARC4::~ARC4()
{
    m_x=0;
    m_y=0;
}

byte ARC4::GetByte()
{
    m_x++;
    m_y += m_state[m_x];
	std::swap(m_state[m_x], m_state[m_y]);
    return (m_state[(m_state[m_x] + m_state[m_y]) & 255]);
}

byte ARC4::ProcessByte(byte input)
{
    m_x++;
    m_y += m_state[m_x];
	std::swap(m_state[m_x], m_state[m_y]);
    return input ^ (m_state[(m_state[m_x] + m_state[m_y]) & 255]);
}

void ARC4::ProcessString(byte *outString, const byte *inString, unsigned int length)
{
    byte *const s=m_state;
	unsigned int x = m_x;
	unsigned int y = m_y;

    while(length--)
    {
		x = (x+1) & 0xff;
        unsigned int a = s[x];
        y = (y+a) & 0xff;
        unsigned int b = s[y];
        s[x] = b;
        s[y] = a;
        *outString++ = *inString++ ^ s[(a+b) & 0xff];
    }

	m_x = x;
	m_y = y;
}

void ARC4::ProcessString(byte *inoutString, unsigned int length)
{
    byte *const s=m_state;
	unsigned int x = m_x;
	unsigned int y = m_y;

    while(length--)
    {
		x = (x+1) & 0xff;
        unsigned int a = s[x];
        y = (y+a) & 0xff;
        unsigned int b = s[y];
        s[x] = b;
        s[y] = a;
        *inoutString++ ^= s[(a+b) & 0xff];
    }

	m_x = x;
	m_y = y;
}

NAMESPACE_END
