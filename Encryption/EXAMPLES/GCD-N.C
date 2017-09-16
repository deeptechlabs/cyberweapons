/* Removed restriction on x values, see gcd() for details
   Since few, if any, C compilers handle tail recursion efficiently,
   I've converted this to an iterative algorithm.
		--Ken Pizzini
		ken@halcyon.com
*/
/*
  This algorithm can be generalized to return the GCD of an array
  of m numbers:
*/

#include <stddef.h>

/* returns the GCD of x1, x2...xm, assuming all x values are greater than 0 */

int
multiple_GCD(size_t m, int *x)
{
	size_t i;
	int g;

	if (m < 1)
		return 0;
	g = x[0]
	for (i=1; i<m; ++i) {
		g = gcd(g, x[i]);
		/* optimization, since for random x[i], g==1 60% of the time: */
		if (g == 1)
			return 1;
	}
	return g;
}
