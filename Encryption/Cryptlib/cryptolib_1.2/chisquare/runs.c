/*
 *	G.  Runs Up Test
 */
#include "bash.h"
#define T 6

runs(stream)
register FILE *stream;
{
	double count[T + 1];
	register u;
	register c1, c2;
	int i, r, q, lastu, reject;
	double x2, n, p;

	rewind(stream);
	for (i = 0; i < T + 1; i++)
		count[i] = 0.0;
	n = 0.0;
	r = 0;
	reject = 0;
	q = 0;
	while ((c1 = getc(stream))!= EOF && (c2 = getc(stream))!= EOF) {
		u = c1 + (c2 << 8);
		if (q++ == 0) {
			lastu = u;
			continue;
		}
		r++;
		if (u == lastu)
			reject++;
		if (u > lastu) {
			lastu = u;
			continue;
		}
		if (reject == 0) {
			if (r >= T)
				count[T] += 1.0;
			else
				count[r] += 1.0;
			n += 1.0;
		}
		r = 0;
		q = 0;		/* skip next item */
		reject = 0;
	}
	x2 = 0;
	for (i = 1; i < T; i++) {
		p = exp(-gamma((double)(i + 1))) - exp(-gamma((double)(i + 2)));
		x2 += (count[i] - n*p)*(count[i] - n*p)/(n*p);
	}
	p = exp(-gamma((double)(T + 1)));
	x2 += (count[T] - n*p)*(count[T] - n*p)/(n*p);
	printf("G. Runs Up Test		CHI = %8f\n", chi(x2, T - 1));
}
