// md2.cpp - modified by Wei Dai from Sun Microsystems's md2.c

/*
SKIP Source Code License Statement:
------------------------------------------------------------------
  Copyright
  Sun Microsystems, Inc.
 
 
  Copyright (C) 1994, 1995 Sun Microsystems, Inc.  All Rights
  Reserved.
 
  Permission is hereby granted, free of charge, to any person
  obtaining a copy of this software and associated documentation
  files (the "Software"), to deal in the Software without
  restriction, including without limitation the rights to use,
  copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software or derivatives of the Software, and to 
  permit persons to whom the Software or its derivatives is furnished 
  to do so, subject to the following conditions:
 
  The above copyright notice and this permission notice shall be
  included in all copies or substantial portions of the Software.
 
  The Software must not be transferred to persons who are not US
  citizens or permanent residents of the US or exported outside
  the US (except Canada) in any form (including by electronic
  transmission) without prior written approval from the US
  Government. Non-compliance with these restrictions constitutes
  a violation of the U.S. Export Control Laws.
 
  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
  OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  NONINFRINGEMENT.  IN NO EVENT SHALL SUN MICROSYSTEMS, INC., BE LIABLE
  FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
  CONNECTION WITH THE SOFTWARE OR DERIVATES OF THIS SOFTWARE OR 
  THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 
  Except as contained in this notice, the name of Sun Microsystems, Inc.
  shall not be used in advertising or otherwise to promote
  the sale, use or other dealings in this Software or its derivatives 
  without prior written authorization from Sun Microsystems, Inc.
*/

#include "pch.h"
#include "md2.h"

NAMESPACE_BEGIN(CryptoPP)

MD2::MD2()
	: buf(64)
{
	Init();
}

void MD2::Init()
{
	memset(buf, 0, 64);
	len = 0;
}

void MD2::Update(const byte *input, unsigned int length)
{
	while (length)
	{
		unsigned int lenInc = STDMIN(length, 16-len);
		memcpy(buf+len+16, input, lenInc);
		input += lenInc;
		length -= lenInc;
		len += lenInc;

		if (len == 16)
		{
			Transform();
			len = 0;
		}
	}
}

void MD2::Final(byte *hash)
{
	byte space = 16 - len; // Amount of padding

	// Pad with "space" bytes of value "space"
	memset(buf+16+len, space, space);
	Transform();

	// Append checksum
	memcpy(buf+16, buf+48, 16);
	// The transform redundantly updates the checksum, but it's not worth optimizing away.
	Transform();

	// Copy hash out
	memcpy(hash, buf, 16);

	Init();
}

void MD2::Transform()
{
	static const byte permutation[256] = {
		 41, 46, 67,201,162,216,124,  1, 61, 54, 84,161,236,240,  6, 19,
		 98,167,  5,243,192,199,115,140,152,147, 43,217,188, 76,130,202,
		 30,155, 87, 60,253,212,224, 22,103, 66,111, 24,138, 23,229, 18,
		190, 78,196,214,218,158,222, 73,160,251,245,142,187, 47,238,122,
		169,104,121,145, 21,178,  7, 63,148,194, 16,137, 11, 34, 95, 33,
		128,127, 93,154, 90,144, 50, 39, 53, 62,204,231,191,247,151,  3,
		255, 25, 48,179, 72,165,181,209,215, 94,146, 42,172, 86,170,198,
		 79,184, 56,210,150,164,125,182,118,252,107,226,156,116,  4,241,
		 69,157,112, 89,100,113,135, 32,134, 91,207,101,230, 45,168,  2,
		 27, 96, 37,173,174,176,185,246, 28, 70, 97,105, 52, 64,126, 15,
		 85, 71,163, 35,221, 81,175, 58,195, 92,249,206,186,197,234, 38,
		 44, 83, 13,110,133, 40,132,  9,211,223,205,244, 65,129, 77, 82,
		106,220, 55,200,108,193,171,250, 36,225,123,  8, 12,189,177, 74,
		120,136,149,139,227, 99,232,109,233,203,213,254, 59,  0, 29, 57,
		242,239,183, 14,102, 88,208,228,166,119,114,248,235,117, 75, 10,
		 49, 68, 80,180,143,237, 31, 26,219,153,141, 51,159, 17,131, 20
	};

	// Fill in the temp buf
	unsigned int i;
	for (i = 0; i < 16; i++)
			buf[i+32] = buf[i+16] ^ buf[i];

	// Update the checksum in the last 16 bytes of the buf
	byte t = buf[63];
	for (i = 0; i < 16; i++)
		t = buf[48+i] ^= permutation[buf[16+i] ^ t];

	// 18 passes of encryption over the first 48 bytes of the buf
	t = 0;
	for (i = 0; i < 18; i++)
	{
		for (unsigned int j = 0; j < 48; j++)
			t = buf[j] ^= permutation[t];
		t += i;
	}
}

NAMESPACE_END
