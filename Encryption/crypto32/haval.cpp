// haval.cpp - modified by Wei Dai from Yuliang Zheng's HAVAL.c
// distributed with Yuliang Zheng's permission

/*
 *  Reference:
 *       Y. Zheng, J. Pieprzyk and J. Seberry:
 *       ``HAVAL --- a one-way hashing algorithm with variable
 *       length of output'', Advances in Cryptology --- AUSCRYPT'92,
 *       Lecture Notes in Computer Science, Springer-Verlag, 1993.
 *
 *  Author:     Yuliang Zheng
 *              Department of Computer Science
 *              University of Wollongong
 *              Wollongong, NSW 2522, Australia
 *              Email: yuliang@cs.uow.edu.au
 *              Voice: +61 42 21 4331 (office)
 */

#include "pch.h"
#include "haval.h"

NAMESPACE_BEGIN(CryptoPP)

HAVAL::HAVAL(unsigned int digestSize, unsigned int pass)
	: IteratedHash<word32>(DATASIZE, DIGESTSIZE),
	  digestSize(digestSize), pass(pass)
{
	assert(digestSize >= 16 && digestSize <= 32 && digestSize%4==0);
	assert(pass >= 3 && pass <= 5);

	Init();
}

void HAVAL::Init()
{
	countLo = countHi = 0;

	digest[0] = 0x243F6A88;
	digest[1] = 0x85A308D3;
	digest[2] = 0x13198A2E;
	digest[3] = 0x03707344;
	digest[4] = 0xA4093822;
	digest[5] = 0x299F31D0;
	digest[6] = 0x082EFA98;
	digest[7] = 0xEC4E6C89;
}

inline void HAVAL::vTransform(word32 *buf, const word32 *in)
{
	if (pass==3)
		HAVAL3::Transform(buf, in);
	else if (pass==4)
		HAVAL4::Transform(buf, in);
	else
		HAVAL5::Transform(buf, in);
}

void HAVAL::HashBlock(const word32 *input)
{
#ifdef IS_LITTLE_ENDIAN
	vTransform(digest, input);
#else
	byteReverse(data.ptr, input, (unsigned int)DATASIZE);
	vTransform(digest, data);
#endif
}

void HAVAL::Final (byte *hash)
{
	PadLastBlock(118, 1);	// first byte of padding for HAVAL is 1 instead of 0x80
	CorrectEndianess(data, data, 120);

	data[29] &= 0xffff;
	data[29] |= ((word32)digestSize<<25) | ((word32)pass<<19) | ((word32)VERSION<<16);
	data[30] = countLo;
	data[31] = countHi;

	vTransform(digest, data);
	Tailor(digestSize*8);
	CorrectEndianess(digest, digest, digestSize);
	memcpy(hash, digest, digestSize);

	Init();		// reinit for next use
}

// tailor the last output
void HAVAL::Tailor(unsigned int FPTLEN)
{
	word32 temp;

	switch (FPTLEN)
	{
	case 128:
		temp = (digest[7] & 0x000000FF) | 
			   (digest[6] & 0xFF000000) | 
			   (digest[5] & 0x00FF0000) | 
			   (digest[4] & 0x0000FF00);
		digest[0] += rotrFixed(temp,  8U);

		temp = (digest[7] & 0x0000FF00) | 
			   (digest[6] & 0x000000FF) | 
			   (digest[5] & 0xFF000000) | 
			   (digest[4] & 0x00FF0000);
		digest[1] += rotrFixed(temp, 16U);

		temp  = (digest[7] & 0x00FF0000) | 
				(digest[6] & 0x0000FF00) | 
				(digest[5] & 0x000000FF) | 
				(digest[4] & 0xFF000000);
		digest[2] += rotrFixed(temp, 24U);

		temp = (digest[7] & 0xFF000000) | 
			   (digest[6] & 0x00FF0000) | 
			   (digest[5] & 0x0000FF00) | 
			   (digest[4] & 0x000000FF);
		digest[3] += temp;
		break;

	case 160:
		temp = (digest[7] &  (word32)0x3F) | 
			   (digest[6] & ((word32)0x7F << 25)) |  
			   (digest[5] & ((word32)0x3F << 19));
		digest[0] += rotrFixed(temp, 19U);

		temp = (digest[7] & ((word32)0x3F <<  6)) | 
			   (digest[6] &  (word32)0x3F) |  
			   (digest[5] & ((word32)0x7F << 25));
		digest[1] += rotrFixed(temp, 25U);

		temp = (digest[7] & ((word32)0x7F << 12)) | 
			   (digest[6] & ((word32)0x3F <<  6)) |  
			   (digest[5] &  (word32)0x3F);
		digest[2] += temp;

		temp = (digest[7] & ((word32)0x3F << 19)) | 
			   (digest[6] & ((word32)0x7F << 12)) |  
			   (digest[5] & ((word32)0x3F <<  6));
		digest[3] += temp >> 6; 

		temp = (digest[7] & ((word32)0x7F << 25)) | 
			   (digest[6] & ((word32)0x3F << 19)) |  
			   (digest[5] & ((word32)0x7F << 12));
		digest[4] += temp >> 12;
		break;

	case 192:
		temp = (digest[7] &  (word32)0x1F) | 
			   (digest[6] & ((word32)0x3F << 26));
		digest[0] += rotrFixed(temp, 26U);

		temp = (digest[7] & ((word32)0x1F <<  5)) | 
			   (digest[6] &  (word32)0x1F);
		digest[1] += temp;

		temp = (digest[7] & ((word32)0x3F << 10)) | 
			   (digest[6] & ((word32)0x1F <<  5));
		digest[2] += temp >> 5;

		temp = (digest[7] & ((word32)0x1F << 16)) | 
			   (digest[6] & ((word32)0x3F << 10));
		digest[3] += temp >> 10;

		temp = (digest[7] & ((word32)0x1F << 21)) | 
			   (digest[6] & ((word32)0x1F << 16));
		digest[4] += temp >> 16;

		temp = (digest[7] & ((word32)0x3F << 26)) | 
			   (digest[6] & ((word32)0x1F << 21));
		digest[5] += temp >> 21;
		break;

	case 224:
		digest[0] += (digest[7] >> 27) & 0x1F;
		digest[1] += (digest[7] >> 22) & 0x1F;
		digest[2] += (digest[7] >> 18) & 0x0F;
		digest[3] += (digest[7] >> 13) & 0x1F;
		digest[4] += (digest[7] >>  9) & 0x0F;
		digest[5] += (digest[7] >>  4) & 0x1F;
		digest[6] +=  digest[7]        & 0x0F;
		break;

	case 256:
		break;

	default:
		assert(false);
	}
}

/*
#define f_1(x6, x5, x4, x3, x2, x1, x0)          \
		   ((x1) & ((x0) ^ (x4)) ^ (x2) & (x5) ^ \
			(x3) & (x6) ^ (x0))
*/

#define f_1(x6, x5, x4, x3, x2, x1, x0)          \
	((x1&(x0^x4)) ^ (x2&x5) ^ (x3&x6) ^ x0)

/*
#define f_2(x6, x5, x4, x3, x2, x1, x0)                         \
		   ((x2) & ((x1) & ~(x3) ^ (x4) & (x5) ^ (x6) ^ (x0)) ^ \
			(x4) & ((x1) ^ (x5)) ^ (x3) & (x5) ^ (x0))
*/

#define f_2(x6, x5, x4, x3, x2, x1, x0)                         \
	(((x4&x5)|x2) ^ (x0|x2) ^ (x2&((x1&~x3)^x6)) ^ (x3&x5) ^ (x1&x4))

/*
#define f_3(x6, x5, x4, x3, x2, x1, x0)          \
		   ((x3) & ((x1) & (x2) ^ (x6) ^ (x0)) ^ \
			(x1) & (x4) ^ (x2) & (x5) ^ (x0))
*/

#define f_3(x6, x5, x4, x3, x2, x1, x0)          \
	((x3 & ((x1&x2) ^ x6 ^ x0)) ^ (x1&x4) ^ (x2&x5) ^ x0)

/*
#define f_4(x6, x5, x4, x3, x2, x1, x0)                                 \
		   ((x4) & ((x5) & ~(x2) ^ (x3) & ~(x6) ^ (x1) ^ (x6) ^ (x0)) ^ \
			(x3) & ((x1) & (x2) ^ (x5) ^ (x6)) ^                        \
			(x2) & (x6) ^ (x0))
*/

#define f_4(x6, x5, x4, x3, x2, x1, x0)          \
	((((~x2&x5)^(x3|x6)^x1^x0)&x4) ^ (((x1&x2)^x5^x6)&x3) ^ (x2&x6) ^ x0)


/*
#define f_5(x6, x5, x4, x3, x2, x1, x0)             \
		   ((x0) & ((x1) & (x2) & (x3) ^ ~(x5)) ^   \
			(x1) & (x4) ^ (x2) & (x5) ^ (x3) & (x6))
*/

#define f_5(x6, x5, x4, x3, x2, x1, x0)          \
	((((x0&x2&x3)^x4)&x1) ^ ((x0^x2)&x5) ^ (x3&x6) ^ x0)

/*
 * Permutations phi_{i,j}, i=3,4,5, j=1,...,i.
 *
 * PASS = 3:
 *               6 5 4 3 2 1 0
 *               | | | | | | | (replaced by)
 *  phi_{3,1}:   1 0 3 5 6 2 4
 *  phi_{3,2}:   4 2 1 0 5 3 6
 *  phi_{3,3}:   6 1 2 3 4 5 0
 *
 * PASS = 4:
 *               6 5 4 3 2 1 0
 *               | | | | | | | (replaced by)
 *  phi_{4,1}:   2 6 1 4 5 3 0
 *  phi_{4,2}:   3 5 2 0 1 6 4
 *  phi_{4,3}:   1 4 3 6 0 2 5
 *  phi_{4,4}:   6 4 0 5 2 1 3
 *
 * PASS = 5:
 *               6 5 4 3 2 1 0
 *               | | | | | | | (replaced by)
 *  phi_{5,1}:   3 4 1 0 5 2 6
 *  phi_{5,2}:   6 2 1 0 3 4 5
 *  phi_{5,3}:   2 6 0 4 3 1 5
 *  phi_{5,4}:   1 5 3 2 0 4 6
 *  phi_{5,5}:   2 5 0 6 4 3 1
 */

#define Fphi_31(x6, x5, x4, x3, x2, x1, x0) \
			f_1(x1, x0, x3, x5, x6, x2, x4)

#define Fphi_41(x6, x5, x4, x3, x2, x1, x0) \
			f_1(x2, x6, x1, x4, x5, x3, x0)

#define Fphi_51(x6, x5, x4, x3, x2, x1, x0) \
			f_1(x3, x4, x1, x0, x5, x2, x6)

#define Fphi_32(x6, x5, x4, x3, x2, x1, x0) \
			f_2(x4, x2, x1, x0, x5, x3, x6)

#define Fphi_42(x6, x5, x4, x3, x2, x1, x0) \
			f_2(x3, x5, x2, x0, x1, x6, x4)

#define Fphi_52(x6, x5, x4, x3, x2, x1, x0) \
			f_2(x6, x2, x1, x0, x3, x4, x5)

#define Fphi_33(x6, x5, x4, x3, x2, x1, x0) \
			f_3(x6, x1, x2, x3, x4, x5, x0)

#define Fphi_43(x6, x5, x4, x3, x2, x1, x0) \
			f_3(x1, x4, x3, x6, x0, x2, x5)

#define Fphi_53(x6, x5, x4, x3, x2, x1, x0) \
			f_3(x2, x6, x0, x4, x3, x1, x5)

#define Fphi_44(x6, x5, x4, x3, x2, x1, x0) \
			f_4(x6, x4, x0, x5, x2, x1, x3)

#define Fphi_54(x6, x5, x4, x3, x2, x1, x0) \
			f_4(x1, x5, x3, x2, x0, x4, x6)

#define Fphi_55(x6, x5, x4, x3, x2, x1, x0) \
			f_5(x2, x5, x0, x6, x4, x3, x1)

#define FF(Fphi, x7, x6, x5, x4, x3, x2, x1, x0, w, c)	\
	  x7 = rotrFixed(Fphi(x6, x5, x4, x3, x2, x1, x0), 7U) + rotrFixed(x7, 11U) + w + c;

#define Round1(Fphi)											\
	for (i=0; i<4; i++)											\
	{															\
		FF(Fphi, t7, t6, t5, t4, t3, t2, t1, t0, w[8*i+0], 0);	\
		FF(Fphi, t6, t5, t4, t3, t2, t1, t0, t7, w[8*i+1], 0);	\
		FF(Fphi, t5, t4, t3, t2, t1, t0, t7, t6, w[8*i+2], 0);	\
		FF(Fphi, t4, t3, t2, t1, t0, t7, t6, t5, w[8*i+3], 0);	\
		FF(Fphi, t3, t2, t1, t0, t7, t6, t5, t4, w[8*i+4], 0);	\
		FF(Fphi, t2, t1, t0, t7, t6, t5, t4, t3, w[8*i+5], 0);	\
		FF(Fphi, t1, t0, t7, t6, t5, t4, t3, t2, w[8*i+6], 0);	\
		FF(Fphi, t0, t7, t6, t5, t4, t3, t2, t1, w[8*i+7], 0);	\
	}

#define Round2(Fphi)															\
	for (i=0; i<4; i++)															\
	{																			\
		FF(Fphi, t7, t6, t5, t4, t3, t2, t1, t0, w[wi2[8*i+0]], mc2[8*i+0]);	\
		FF(Fphi, t6, t5, t4, t3, t2, t1, t0, t7, w[wi2[8*i+1]], mc2[8*i+1]);	\
		FF(Fphi, t5, t4, t3, t2, t1, t0, t7, t6, w[wi2[8*i+2]], mc2[8*i+2]);	\
		FF(Fphi, t4, t3, t2, t1, t0, t7, t6, t5, w[wi2[8*i+3]], mc2[8*i+3]);	\
		FF(Fphi, t3, t2, t1, t0, t7, t6, t5, t4, w[wi2[8*i+4]], mc2[8*i+4]);	\
		FF(Fphi, t2, t1, t0, t7, t6, t5, t4, t3, w[wi2[8*i+5]], mc2[8*i+5]);	\
		FF(Fphi, t1, t0, t7, t6, t5, t4, t3, t2, w[wi2[8*i+6]], mc2[8*i+6]);	\
		FF(Fphi, t0, t7, t6, t5, t4, t3, t2, t1, w[wi2[8*i+7]], mc2[8*i+7]);	\
	}

#define Round3(Fphi)															\
	for (i=0; i<4; i++)															\
	{																			\
		FF(Fphi, t7, t6, t5, t4, t3, t2, t1, t0, w[wi3[8*i+0]], mc3[8*i+0]);	\
		FF(Fphi, t6, t5, t4, t3, t2, t1, t0, t7, w[wi3[8*i+1]], mc3[8*i+1]);	\
		FF(Fphi, t5, t4, t3, t2, t1, t0, t7, t6, w[wi3[8*i+2]], mc3[8*i+2]);	\
		FF(Fphi, t4, t3, t2, t1, t0, t7, t6, t5, w[wi3[8*i+3]], mc3[8*i+3]);	\
		FF(Fphi, t3, t2, t1, t0, t7, t6, t5, t4, w[wi3[8*i+4]], mc3[8*i+4]);	\
		FF(Fphi, t2, t1, t0, t7, t6, t5, t4, t3, w[wi3[8*i+5]], mc3[8*i+5]);	\
		FF(Fphi, t1, t0, t7, t6, t5, t4, t3, t2, w[wi3[8*i+6]], mc3[8*i+6]);	\
		FF(Fphi, t0, t7, t6, t5, t4, t3, t2, t1, w[wi3[8*i+7]], mc3[8*i+7]);	\
	}

#define Round4(Fphi)															\
	for (i=0; i<4; i++)															\
	{																			\
		FF(Fphi, t7, t6, t5, t4, t3, t2, t1, t0, w[wi4[8*i+0]], mc4[8*i+0]);	\
		FF(Fphi, t6, t5, t4, t3, t2, t1, t0, t7, w[wi4[8*i+1]], mc4[8*i+1]);	\
		FF(Fphi, t5, t4, t3, t2, t1, t0, t7, t6, w[wi4[8*i+2]], mc4[8*i+2]);	\
		FF(Fphi, t4, t3, t2, t1, t0, t7, t6, t5, w[wi4[8*i+3]], mc4[8*i+3]);	\
		FF(Fphi, t3, t2, t1, t0, t7, t6, t5, t4, w[wi4[8*i+4]], mc4[8*i+4]);	\
		FF(Fphi, t2, t1, t0, t7, t6, t5, t4, t3, w[wi4[8*i+5]], mc4[8*i+5]);	\
		FF(Fphi, t1, t0, t7, t6, t5, t4, t3, t2, w[wi4[8*i+6]], mc4[8*i+6]);	\
		FF(Fphi, t0, t7, t6, t5, t4, t3, t2, t1, w[wi4[8*i+7]], mc4[8*i+7]);	\
	}

#define Round5(Fphi)															\
	for (i=0; i<4; i++)															\
	{																			\
		FF(Fphi, t7, t6, t5, t4, t3, t2, t1, t0, w[wi5[8*i+0]], mc5[8*i+0]);	\
		FF(Fphi, t6, t5, t4, t3, t2, t1, t0, t7, w[wi5[8*i+1]], mc5[8*i+1]);	\
		FF(Fphi, t5, t4, t3, t2, t1, t0, t7, t6, w[wi5[8*i+2]], mc5[8*i+2]);	\
		FF(Fphi, t4, t3, t2, t1, t0, t7, t6, t5, w[wi5[8*i+3]], mc5[8*i+3]);	\
		FF(Fphi, t3, t2, t1, t0, t7, t6, t5, t4, w[wi5[8*i+4]], mc5[8*i+4]);	\
		FF(Fphi, t2, t1, t0, t7, t6, t5, t4, t3, w[wi5[8*i+5]], mc5[8*i+5]);	\
		FF(Fphi, t1, t0, t7, t6, t5, t4, t3, t2, w[wi5[8*i+6]], mc5[8*i+6]);	\
		FF(Fphi, t0, t7, t6, t5, t4, t3, t2, t1, w[wi5[8*i+7]], mc5[8*i+7]);	\
	}

const unsigned int HAVAL::wi2[32] = { 5,14,26,18,11,28, 7,16, 0,23,20,22, 1,10, 4, 8,30, 3,21, 9,17,24,29, 6,19,12,15,13, 2,25,31,27};
const unsigned int HAVAL::wi3[32] = {19, 9, 4,20,28,17, 8,22,29,14,25,12,24,30,16,26,31,15, 7, 3, 1, 0,18,27,13, 6,21,10,23,11, 5, 2};
const unsigned int HAVAL::wi4[32] = {24, 4, 0,14, 2, 7,28,23,26, 6,30,20,18,25,19, 3,22,11,31,21, 8,27,12, 9, 1,29, 5,15,17,10,16,13};
const unsigned int HAVAL::wi5[32] = {27, 3,21,26,17,11,20,29,19, 0,12, 7,13, 8,31,10, 5, 9,14,30,18, 6,28,24, 2,23,16,22, 4, 1,25,15};

const word32 HAVAL::mc2[32] = {
  0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C, 0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917
, 0x9216D5D9, 0x8979FB1B, 0xD1310BA6, 0x98DFB5AC, 0x2FFD72DB, 0xD01ADFB7, 0xB8E1AFED, 0x6A267E96
, 0xBA7C9045, 0xF12C7F99, 0x24A19947, 0xB3916CF7, 0x0801F2E2, 0x858EFC16, 0x636920D8, 0x71574E69
, 0xA458FEA3, 0xF4933D7E, 0x0D95748F, 0x728EB658, 0x718BCD58, 0x82154AEE, 0x7B54A41D, 0xC25A59B5};

const word32 HAVAL::mc3[32] = {
0x9C30D539,0x2AF26013,0xC5D1B023,0x286085F0,0xCA417918,0xB8DB38EF,0x8E79DCB0,0x603A180E,
0x6C9E0E8B,0xB01E8A3E,0xD71577C1,0xBD314B27,0x78AF2FDA,0x55605C60,0xE65525F3,0xAA55AB94,
0x57489862,0x63E81440,0x55CA396A,0x2AAB10B6,0xB4CC5C34,0x1141E8CE,0xA15486AF,0x7C72E993,
0xB3EE1411,0x636FBC2A,0x2BA9C55D,0x741831F6,0xCE5C3E16,0x9B87931E,0xAFD6BA33,0x6C24CF5C};

const word32 HAVAL::mc4[32] = {
0x7A325381,0x28958677,0x3B8F4898,0x6B4BB9AF,0xC4BFE81B,0x66282193,0x61D809CC,0xFB21A991,
0x487CAC60,0x5DEC8032,0xEF845D5D,0xE98575B1,0xDC262302,0xEB651B88,0x23893E81,0xD396ACC5,
0x0F6D6FF3,0x83F44239,0x2E0B4482,0xA4842004,0x69C8F04A,0x9E1F9B5E,0x21C66842,0xF6E96C9A,
0x670C9C61,0xABD388F0,0x6A51A0D2,0xD8542F68,0x960FA728,0xAB5133A3,0x6EEF0B6C,0x137A3BE4};

const word32 HAVAL::mc5[32] = {
0xBA3BF050,0x7EFB2A98,0xA1F1651D,0x39AF0176,0x66CA593E,0x82430E88,0x8CEE8619,0x456F9FB4,
0x7D84A5C3,0x3B8B5EBE,0xE06F75D8,0x85C12073,0x401A449F,0x56C16AA6,0x4ED3AA62,0x363F7706,
0x1BFEDF72,0x429B023D,0x37D0D724,0xD00A1248,0xDB0FEAD3,0x49F1C09B,0x075372C9,0x80991B7B,
0x25D479D8,0xF6E8DEF7,0xE3FE501A,0xB6794C3B,0x976CE0BD,0x04C006BA,0xC1A94FB6,0x409F60C4};

void HAVAL3::Transform (word32 *digest, const word32 *w)
{
	register word32 t0 = digest[0],    // make use of
					t1 = digest[1],    // internal registers
					t2 = digest[2],
					t3 = digest[3],
					t4 = digest[4],
					t5 = digest[5],
					t6 = digest[6],
					t7 = digest[7];
	unsigned i;

	Round1(Fphi_31);
	Round2(Fphi_32);
	Round3(Fphi_33);

	digest[0] += t0;
	digest[1] += t1;
	digest[2] += t2;
	digest[3] += t3;
	digest[4] += t4;
	digest[5] += t5;
	digest[6] += t6;
	digest[7] += t7;
}

void HAVAL4::Transform (word32 *digest, const word32 *w)
{
	register word32 t0 = digest[0],    // make use of
					t1 = digest[1],    // internal registers
					t2 = digest[2],
					t3 = digest[3],
					t4 = digest[4],
					t5 = digest[5],
					t6 = digest[6],
					t7 = digest[7];
	unsigned i;

	Round1(Fphi_41);
	Round2(Fphi_42);
	Round3(Fphi_43);
	Round4(Fphi_44);

	digest[0] += t0;
	digest[1] += t1;
	digest[2] += t2;
	digest[3] += t3;
	digest[4] += t4;
	digest[5] += t5;
	digest[6] += t6;
	digest[7] += t7;
}

void HAVAL5::Transform (word32 *digest, const word32 *w)
{
	register word32 t0 = digest[0],    // make use of
					t1 = digest[1],    // internal registers
					t2 = digest[2],
					t3 = digest[3],
					t4 = digest[4],
					t5 = digest[5],
					t6 = digest[6],
					t7 = digest[7];
	unsigned i;

	Round1(Fphi_51);
	Round2(Fphi_52);
	Round3(Fphi_53);
	Round4(Fphi_54);
	Round5(Fphi_55);

	digest[0] += t0;
	digest[1] += t1;
	digest[2] += t2;
	digest[3] += t3;
	digest[4] += t4;
	digest[5] += t5;
	digest[6] += t6;
	digest[7] += t7;
}

NAMESPACE_END
