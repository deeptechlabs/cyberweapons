/*
 *	E.  Coupon Collector Test
 */
#include "bash.h"
#define T 40
#define D 8

static double p[T + 1] = {
.0,
.0,
.0,
.0,
.0,
.0,
.0,
.0,
.00240325927734,
.00841140747070,
.01734852790832,
.02759993076324,
.03754329867660,
.04601425956934,
.05239733029156,
.05652954569086,
.05855032208955,
.05876432966601,
.05754012738343,
.05524530368372,
.05221059806429,
.04871408171819,
.04497782619043,
.04117152575675,
.03741940106626,
.03380813801559,
.03039460507986,
.02721273053625,
.02427930679575,
.02159870585174,
.01916659972429,
.01697282551245,
.01500354421197,
.01324283325472,
.01167383518954,
.01027956495032,
.00904345885329,
.00794973128078,
.00698359044693,
.00613135270278,
.04341810232698,
};

coupon(stream)
register FILE *stream;
{
	double count[T + 1];
	int occurs[D];
	register u;
	int i, r, q;
	double x2, n;

	rewind(stream);
	for (i = 0; i < T + 1; i++)
		count[i] = 0.0;
	n = 0.0;
	r = 0;
	q = 0;
	for (i = 0; i < D; i++)
		occurs[i] = 0;
	while ((u = getc(stream)) != EOF) {
		u = u & 07;
		r++;
		if (occurs[u])
			continue;
		else {
			occurs[u]++;
			q++;
			if (q < D)
				continue;
			if (r >= T)
				count[T] += 1.0;
			else
				count[r] += 1.0;
			n += 1.0;
			q = 0;
			r = 0;
			for (i = 0; i < D; i++)
				occurs[i] = 0;
		}
	}
	x2 = 0;
	for (i = 8; i < T; i++) {
/*
printf("%f %d %f\n", p[i], count[i], n);
*/
		x2 += (count[i] - n*p[i])*(count[i] - n*p[i])/(n*p[i]);
	}
	x2 += (count[T] - n*p[i])*(count[T] - n*p[i])/(n*p[i]);
	printf("E. Coupon Test		CHI = %8f\n", chi(x2, T - D));
}
