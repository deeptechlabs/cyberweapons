/*
 *	D. Poker Test
 */
#include "bash.h"

extern double pcount[65536];
extern double npairs;

poker()
{
	register a, b, c, d;
	register i;
	double alldiff, onepair, twopair, threekind, fourkind;
	double p, x2;

	alldiff = 0.0;
	onepair = 0.0;
	twopair = 0.0;
	threekind = 0.0;
	fourkind = 0.0;
	for (i = 0; i < 65536; i++) {
		a = (i >> 12) & 0xf;
		b = (i >>  8) & 0xf;
		c = (i >>  4) & 0xf;
		d = (i >>  0) & 0xf;
		if (a == b && a == c && a == d)
			fourkind += pcount[i];
		else if ((a == b && a == c)||(a == b && a == d)||
			 (a == c && a == d)||(b == c && b == d))
			threekind += pcount[i];
		else if ((a == b && c == d)||(a == d && b == c)||
			 (a == c && b == d))
			twopair += pcount[i];
		else if (a == b || a == c || a == d || b == c || b == d || c == d)
			onepair += pcount[i];
		else
			alldiff += pcount[i];
	}
	p = 16.0 * 15.0 * 14.0 * 13.0 / 65536.0;
	x2 = (alldiff - npairs*p)*(alldiff - npairs*p)/(npairs*p);
	p = 16.0 * 15.0 * 14.0 * 6.0 / 65536.0;
	x2 += (onepair - npairs*p)*(onepair - npairs*p)/(npairs*p);
	p = 16.0 * 15.0 * 3.0 / 65536.0;
	x2 += (twopair - npairs*p)*(twopair - npairs*p)/(npairs*p);
	p = 16.0 * 15.0 * 4.0 / 65536.0;
	x2 += (threekind - npairs*p)*(threekind - npairs*p)/(npairs*p);
	p = 16.0 / 65536.0;
	x2 += (fourkind - npairs*p)*(fourkind - npairs*p)/(npairs*p);
	printf("D. Poker Test		CHI = %8f\n", chi(x2, 4));
}
