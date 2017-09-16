// rc5.cpp - written and placed in the public domain by Wei Dai

#include "pch.h"
#include "rc5.h"

NAMESPACE_BEGIN(CryptoPP)

RC5Base::RC5Base(const byte *k, unsigned int keylen, unsigned int rounds)
	: r(rounds), sTable(2*(r+1))
{
	assert(keylen == KeyLength(keylen));

	static const RC5_WORD MAGIC_P = 0xb7e15163L;    // magic constant P for wordsize
	static const RC5_WORD MAGIC_Q = 0x9e3779b9L;    // magic constant Q for wordsize
	static const int U=sizeof(RC5_WORD);

	const unsigned int c=(keylen+U-1)/U;
	SecBlock<RC5_WORD> l(c);

	GetUserKeyLittleEndian(l.ptr, c, k, keylen);

	sTable[0] = MAGIC_P;
	for (unsigned j=1; j<sTable.size;j++)
		sTable[j] = sTable[j-1] + MAGIC_Q;

	RC5_WORD a=0, b=0;
	const unsigned n = 3*STDMAX(sTable.size,c);

	for (unsigned h=0; h < n; h++)
	{
		a = sTable[h % sTable.size] = rotlFixed((sTable[h % sTable.size] + a + b), 3);
		b = l[h % c] = rotlMod((l[h % c] + a + b), (a+b));
	}
}

void RC5Encryption::ProcessBlock(const byte *in, byte *out) const
{
	const RC5_WORD *sptr = sTable;
	RC5_WORD a, b;

	GetBlockLittleEndian(in, a, b);
	a += sptr[0];
	b += sptr[1];
	sptr += 2;

	for(unsigned i=0; i<r; i++)
	{
		a = rotlMod(a^b,b) + sptr[2*i+0];
		b = rotlMod(a^b,a) + sptr[2*i+1];
	}

	PutBlockLittleEndian(out, a, b);
}

void RC5Decryption::ProcessBlock(const byte *in, byte *out) const
{
	const RC5_WORD *sptr = sTable+sTable.size;
	RC5_WORD a, b;

	GetBlockLittleEndian(in, a, b);

	for (unsigned i=0; i<r; i++)
	{
		sptr-=2;
		b = rotrMod(b-sptr[1], a) ^ a;
		a = rotrMod(a-sptr[0], b) ^ b;
	}
	b -= sTable[1];
	a -= sTable[0];

	PutBlockLittleEndian(out, a, b);
}

NAMESPACE_END
