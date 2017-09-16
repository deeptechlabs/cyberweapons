/*
 *	I. mtuple test
 */
#include "bash.h"
#include <stdio.h>

mtuple(stream)
register FILE *stream;
{
	double triples[512];
	double pairs[64];
	register a, b, c;
	register i;
	int n;
	double q3, q2, mean;

	rewind(stream);
	for (i = 0; i < 512; i++)
		triples[i] = 0.0;
	for (i = 0; i < 64; i++)
		pairs[i] = 0.0;
	n = 0;
	a = getc(stream);
	b = getc(stream);
	c = getc(stream);
	if (c == EOF)
		return;
	do {
		i = ((a & 7)) | ((b & 7) << 3) | ((c & 7) << 6);
		triples[i] += 1.0;
		i = ((a & 7)) | ((b & 7) << 3);
		pairs[i] += 1.0;
		n++;
		a = b;
		b = c;
	} while ((c = getc(stream)) != EOF);
	mean = (double)n/512.0;
	q3 = q2 = 0;
	for (i = 0; i < 512; i++)
		q3 += (double)(triples[i] - mean)*(triples[i] - mean)/mean;
	mean = (double)n/64.0;
	for (i = 0; i < 64; i++)
		q2 += (double)(pairs[i] - mean)*(pairs[i] - mean)/mean;
	printf("I. Lapped M-Tuple Test	CHI = %8f\n", chi(q3-q2, 512-64));
}
