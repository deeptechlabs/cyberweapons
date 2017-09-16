/*
 *	B.  Serial Test
 */
#include "bash.h"

double pcount[65536];
double npairs;

serial(stream)
register FILE *stream;
{
	register c1, c2, i;
	double x2, n, p;

	rewind(stream);
	for (i = 0; i < 65536; i++)
		pcount[i] = 0.0;
	n = 0.0;
	while ((c1 = getc(stream))!= EOF && (c2 = getc(stream))!= EOF) {
		n += 1.0;
		pcount[c1 + (c2 << 8)] += 1.0;
	}
	p = 1.0/65536.0;
	npairs = n;
	if (n*p < 5.0) {
		printf("B. Serial Test		(not enought statistics)\n");
		return;
	}
	x2 = 0;
	for (i = 0; i < 65536; i++)
		x2 += (pcount[i] - n*p)*(pcount[i] - n*p)/(n*p);
	printf("B. Serial Test		CHI = %8f\n", chi(x2, 65536 - 1));
}
