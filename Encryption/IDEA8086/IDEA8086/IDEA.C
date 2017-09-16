/*
 * This code is placed in the public domain.
 * Recognition of its authorship, by Colin Plumb, would be appreciated,
 * but cannot be required under the law of "public domain."
 *
 * This is a simple reference implementation of the IDEA cipher.
 */
 
#include "idea.h"
 
uint16
Mul(uint16 a, uint16 b)
{
	ulong x = (ulong)a * b;
	if (x) {
		a = x>>16;
		b = x;
		return b-a+(b<a);
	} else if (a) {
		return 1-a;
	} else {
		return 1-b;
	}
}
 
void
Idea(uchar *in, uchar *out, uint16 *key)
{
        uint16 round, x0, x1, x2, x3, s1, s2;
 
	x0 = in[0] << 8 | in[1];
	x1 = in[2] << 8 | in[3];
	x2 = in[4] << 8 | in[5];
	x3 = in[6] << 8 | in[7];

        for (round = 8; round > 0; round--) {
                x0 = Mul(x0, *key++);
                x1 += *key++;
                x2 += *key++;
                x3 = Mul(x3, *key++);
 
                s1 = x1;  s2 = x2;
                x2 ^= x0;
                x1 ^= x3;
                x2 = Mul(x2, *key++);
                x1 += x2;
                x1 = Mul(x1, *key++);
                x2 += x1;
 
                x0 ^= x1;
                x3 ^= x2;
                x1 ^= s2;
                x2 ^= s1;
        }
        x0 = Mul(x0, *key++);
        x2 += *key++;
        x1 += *key++;
        x3 = Mul(x3, *key);
 
	out[0] = x0>>8;
	out[1] = x0;
	out[2] = x1>>8;
	out[3] = x1;
	out[4] = x2>>8;
	out[5] = x2;
	out[6] = x3>>8;
	out[7] = x3;
}
