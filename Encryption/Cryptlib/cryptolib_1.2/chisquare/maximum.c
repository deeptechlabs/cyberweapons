/*
 *	H.  Maximum of t Test
 */
#include "bash.h"
#define T 8

maximum(stream)
register FILE *stream;
{
	double count[256];
	register i;
	register u, max;
	double x2, n, p;

	rewind(stream);
	for (i = 0; i < 256; i++)
		count[i] = 0.0;
	n = 0.0;
	for (;;) {
		max = 0;
		for (i = 0; i < T; i++) {
			u = getc(stream);
			if (u == EOF)
				goto out;
			if (u > max)
				max = u;
		}
		count[max] += 1.0;
		n += 1.0;
	}
out:
	x2 = 0;
	for (i = 200; i < 256; i++) {
		p = pow((double)(i + 1)/256.0, (double)T)
		  - pow((double)i/256.0, (double)T);
		x2 += (count[i] - n*p)*(count[i] - n*p)/(n*p);
	}
	printf("H. Max-of-8 Test	CHI = %8f\n", chi(x2, 256 - 200 - 1));
}
