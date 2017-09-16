/*
 *	F.  Permutation Test
 */
#include "bash.h"

permute(stream)
register FILE *stream;
{
	double count[120+1];
	register c0, c1, c2, c3, c4;
	int i;
	double x2, n, p;

	rewind(stream);
	for (i = 0; i < 120+1; i++)
		count[i] = 0.0;
	n = 0.0;
	for (;;) {
		c0 = getc(stream);
		c1 = getc(stream);
		c2 = getc(stream);
		c3 = getc(stream);
		c4 = getc(stream);
		if (c4 == EOF)
			break;
		i = perm(c4, c3, c2, c1, c0);
		count[i] += 1.0;
		if (i < 120)
			n += 1.0;
	}
	x2 = 0;
	p = 1.0/(5.0 * 4.0 * 3.0 * 2.0 * 1.0);
	for (i = 0; i < 120; i++)
		x2 += (count[i] - n*p)*(count[i] - n*p)/(n*p);
	printf("F. Permutations Test	CHI = %8f\n", chi(x2, 120 - 1));
}

perm(a, b, c, d, e)
int a, b, c, d, e;
{
	register s, i;
	register int *u;
	int r, f;
	int au[5];

	au[0] = a;
	au[1] = b;
	au[2] = c;
	au[3] = d;
	au[4] = e;
	u = au;
	f = 0;
	s = 0;
	r = 5;
	for (i = 1; i < r; i++)
		if (u[i] > u[s])
			s = i;
	f = r * f + s;
	--r;
	i = u[s];
	u[s] = u[r];
	u[r] = i;
	s = 0;
	for (i = 1; i < r; i++)
		if (u[i] > u[s])
			s = i;
	f = r * f + s;
	--r;
	i = u[s];
	u[s] = u[r];
	u[r] = i;
	s = 0;
	for (i = 1; i < r; i++)
		if (u[i] > u[s])
			s = i;
	f = r * f + s;
	--r;
	i = u[s];
	u[s] = u[r];
	u[r] = i;
	s = 0;
	for (i = 1; i < r; i++)
		if (u[i] > u[s])
			s = i;
	f = r * f + s;
	--r;
	i = u[s];
	u[s] = u[r];
	u[r] = i;
	if (u[0] == u[1]||u[1] == u[2]||u[2] == u[3]||u[3] == u[4])
		f = 120;
/*
printf("%3d %3d %3d %3d %3d --> %3d\n", u[0], u[1], u[2], u[3], u[4], f);
*/
	return f;
}
