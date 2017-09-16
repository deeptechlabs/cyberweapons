/*
 *	Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
 *	All rights reserved.
 */

#include "prsg.h"

/* Using 159, 31, 0 */
#define mask0	0x80000001
#define mask1	0x00000000
#define mask2	0x00000000
#define mask3	0x00000000
#define mask4	0x80000000

void
prsg_seed(PRSG_INFO * context, unsigned char * seed)
{
	int i;

	/* Ensure we dont seed with all zeros */
	for (i=0; i < 20; i++)
	{
		if (seed[i])
			break;
		if (i == 19)
		{
			seed[0] = 1;
		}
	}

	context->reg[4] = (seed[ 0] << 24) | (seed[ 1] << 16) | (seed[ 2] << 8) | seed[ 3];
	context->reg[3] = (seed[ 4] << 24) | (seed[ 5] << 16) | (seed[ 6] << 8) | seed[ 7];
	context->reg[2] = (seed[ 8] << 24) | (seed[ 9] << 16) | (seed[10] << 8) | seed[11];
	context->reg[1] = (seed[12] << 24) | (seed[13] << 16) | (seed[14] << 8) | seed[15];
	context->reg[0] = (seed[16] << 24) | (seed[17] << 16) | (seed[18] << 8) | seed[19];
}

void
prsg_clock(PRSG_INFO * context)
{
	if (context->reg[0] & 0x00000001)
	{
		context->reg[0] ^= mask0;
		context->reg[1] ^= mask1;
		context->reg[2] ^= mask2;
		context->reg[3] ^= mask3;
		context->reg[4] ^= mask4;

		context->reg[0] = (context->reg[0] >> 1) | ((context->reg[1] & 0x00000001) << 31);
		context->reg[1] = (context->reg[1] >> 1) | ((context->reg[2] & 0x00000001) << 31);
		context->reg[2] = (context->reg[2] >> 1) | ((context->reg[3] & 0x00000001) << 31);
		context->reg[3] = (context->reg[3] >> 1) | ((context->reg[4] & 0x00000001) << 31);
		context->reg[4] = (context->reg[4] >> 1) | 0x80000000;
	}
	else
	{
		context->reg[0] = (context->reg[0] >> 1) | ((context->reg[1] & 0x00000001) << 31);
		context->reg[1] = (context->reg[1] >> 1) | ((context->reg[2] & 0x00000001) << 31);
		context->reg[2] = (context->reg[2] >> 1) | ((context->reg[3] & 0x00000001) << 31);
		context->reg[3] = (context->reg[3] >> 1) | ((context->reg[4] & 0x00000001) << 31);
		context->reg[4] >>= 1;
	}
}
