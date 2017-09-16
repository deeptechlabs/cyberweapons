/*
 *	A.  Frequency Test
 */
#include "bash.h"

frequency(stream)
register FILE *stream;
{
	double count[256];
	double x2, n, p;
	register c, i;

	rewind(stream);
	for (i = 0; i < 256; i++)
		count[i] = 0.0;
	n = 0.0;
	while ((c = getc(stream)) != EOF) {
		n += 1.0;
		count[c] += 1.0;
	}
	p = 1.0/256.0;
	x2 = 0;
	for (i = 0; i < 256; i++)
		x2 += (count[i] - n*p)*(count[i] - n*p)/(n*p);
/*
	printf("A. Frequency Test	CHI = %8f   x2 = %8f\n", chi(x2, 256 - 1), x2);
*/
	printf("A. Frequency Test	CHI = %8f\n", chi(x2, 256 - 1));
/*
	for (i=0; i<256; i++)
	    printf("%d, %f\n",i, count[i]);
	exit(1);
*/

}
