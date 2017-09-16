/*
 *	C.  Gap Test
 */
#include "bash.h"
#define T 16

gap(stream, alpha, beta)
register FILE *stream;
int alpha, beta;
{
	double count[T + 1];
	register u;
	int i, r;
	double x2, n, p, q;

	rewind(stream);
	for (i = 0; i < T + 1; i++)
		count[i] = 0.0;
	n = 0.0;
	r = 0;
	while ((u = getc(stream)) != EOF) {
		if (alpha <= u && u < beta) {
			if (r >= T)
				count[T] += 1.0;
			else
				count[r] += 1.0;
			r = 0;
			n += 1.0;
		} else
			r++;
	}
	p = (double)(beta - alpha)/256.0;
	q = 1.0;
	x2 = 0;
	for (i = 0; i < T; i++) {
		x2 += (count[i] - n*p*q)*(count[i] - n*p*q)/(n*p*q);
		q *= (1.0 - p);
	}
	x2 += (count[T] - n*q)*(count[T] - n*q)/(n*q);
	printf("C. Gap Test		CHI = %8f\n", chi(x2, T));
}
