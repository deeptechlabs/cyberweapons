/*
 *	Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
 *	All rights reserved.
 */

#include "idea.h"

#define KEYS_PER_ROUND	6
#define ROUNDS			8 
#define KEYLEN			(KEYS_PER_ROUND*ROUNDS+4)

/*
 *	Multiplication modulo (2**16)+1
 */
static u_int16_t
mul(u_int16_t a, u_int16_t b)
{
	int32_t p;

	if (a)
	{
		if (b)
		{
			p = a * b;
			b = p & 0xFFFF;
			a = p >> 16;
			return b - a + (b < a);
		}
		else
			return (1 - a);
	}
	return (1 - b); 
}


/*
 * Compute inverse of x, modulo (2**16)+1, using Euclidean gcd algorithm
 */
static u_int16_t
inv(u_int16_t x)
{
	u_int16_t t0, t1, q, y;

	if (x <= 1)	/* Since zero and one are self inverse */
		return x;

	t1 = 0x10001L / x;	/* Since x >= 2, the result is 16bit */
	y = 0x10001L % x;
	if (y == 1)
		return ((1 - t1) & 0xFFFF);

	t0 = 1;
	do
	{
		q = x / y;
		x %= y;
		t0 += q * t1;
		if (x == 1)
			return t0;
		q = y / x;
		y = y % x;
		t1 += q * t0;
	} while (y != 1);

	return (1-t1);
}


/*
 *	Encryption and decryption
 */
void
idea_crypt(u_int16_t * in, u_int16_t * out, u_int16_t * key)
{
	int i = ROUNDS;
	u_int16_t x0, x1, x2, x3, t0, t1;

	x0 = *(in++);
	x1 = *(in++);
	x2 = *(in++);
	x3 = *(in);

	x0 = htons(x0);
	x1 = htons(x1);
	x2 = htons(x2);
	x3 = htons(x3);

	do {
		x0 = mul(x0, *(key++));
		x1 += *(key++);
		x2 += *(key++);
		x3 = mul(x3, *(key++));

		t0 = x2;
		x2 = mul(x0^x2, *(key++));
		t1 = x1;
		x1 = mul((x1^x3)+x2, *(key++));
		x2 += x1;

		x0 ^= x1;
		x3 ^= x2;
		x1 ^= t0;
		x2 ^= t1;

	} while (--i);

	x0 = mul(x0, *(key++));
	t0 = x1;
	x1 = x2 + *(key++);
	x2 = t0 + *(key++);
	x3 = mul(x3, *key);

	x0 = htons(x0);
	x1 = htons(x1);
	x2 = htons(x2);
	x3 = htons(x3);

	*(out++) = x0;
	*(out++) = x1;
	*(out++) = x2;
	*(out) = x3;
}

 
/*
 *	Create decryption key
 */
void
idea_invert_key(u_int16_t * key, u_int16_t * invKey)
{
	int i;

	invKey[KEYS_PER_ROUND * ROUNDS + 0] = inv(*(key++));
	invKey[KEYS_PER_ROUND * ROUNDS + 1] = -*(key++);
	invKey[KEYS_PER_ROUND * ROUNDS + 2] = -*(key++);
	invKey[KEYS_PER_ROUND * ROUNDS + 3] = inv(*(key++));

	for (i = KEYS_PER_ROUND * (ROUNDS-1); i >= 0; i -= KEYS_PER_ROUND)
	{
		invKey[i+4] = *(key++);
		invKey[i+5] = *(key++);
		invKey[i+0] = inv(*(key++));
		if (i > 0)
		{
			invKey[i+2] = -*(key++);
			invKey[i+1] = -*(key++);
		}
		else
		{
			invKey[i+1] = -*(key++);
			invKey[i+2] = -*(key++);
		}
		invKey[i+3]=inv(*(key++));
	}
}


/*
 *	Expand user key of 128 bits to full of 832 bits
 */
void
idea_expand_key(u_int16_t * userKey, u_int16_t * key)
{
	int i, j;

	for(i = 0; i < 8; i++)
		key[i] = htons(userKey[i]);

	j = 0;
	for(; i < KEYLEN; i++)
	{
		j++;
		key[j+7] = (key[j & 7] << 9 | key[(j+1) & 7] >> 7);
		key += j & 8;
		j &= 7;
	}
}
