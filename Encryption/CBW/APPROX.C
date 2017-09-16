/*
 * Fast approximations of useful math functions.
 *
 * Robert W. Baldwin, May 1985.
 */


#include	<stdio.h>
#include	<math.h>
#include	"window.h"
#include	"specs.h"


#define STANDALONE	FALSE

#define	NFEXP		100		/* Number of entries in fexp_value table. */
#define	DXFEXP		0.05	/* Interval width in fexp table. */
#define	MAXFEXP		(NFEXP * DXFEXP)	/* Max value < this */


/* Table of values for exp(-(x*x)/2) starting with zero at intervals of 0.1
 * The values of the derivative of exp(-(x*x)/2) are in fexp_deriv.
 */
float	fexp_value[NFEXP];
float	fexp_deriv[NFEXP];


/* Table for fast square root computation.
 */
float	isqrt[BLOCKSIZE];


#if STANDALONE
main()
{
	int		i;
	float	fi;

	printf("\t\t\t\tTable of exp(-(x*x)/2)");
	printf("\nX\t\treal\t\tapprox");
	printf("\n\n");

	approx_init();

	for (i = 0 ; i < (NFEXP + 5) ; i++)  {
		fi = i;
		fi = fi * DXFEXP;
		fi += DXFEXP/2.0;
		printf("%f\t", fi);
		printf("%f\t", exp(-(fi*fi)/2));
		printf("%f", fexp(fi));
		printf("\n");
		}
}
#endif



/* Initialize the approximation tables.
 */
approx_init()
{
	sqrt_tab();
	fexp_tab();
}


/* Fill in the table of square roots.
 */
sqrt_tab()
{
	reg	int		i;
		float	fi;

	for (i = 0 ; i < BLOCKSIZE ; i++)  {
		fi = i;
		isqrt[i] = sqrt(fi);
		}
}


/* Fill in th approximation table for fexp.
 */
fexp_tab()
{
	int		i;
	float	fi;
	float	value;
	float	deriv;

	for (i = 0 ; i < NFEXP ; i++)  {
		fi = i;
		fi = fi * DXFEXP;
		value = exp(-(fi*fi)/2);
		deriv = -fi * value;
		fexp_value[i] = value;
		fexp_deriv[i] = deriv;
		}
}


/* Return a fast approximation to exp(-(x*x)/2).
 */
float	fexp(x)
reg	float	x;
{
reg	int		index;
	float	approx;
reg	float	result;

	x = abs(x);
	if (x >= MAXFEXP)
		return(0.0);
	index = x * (1.0 / DXFEXP);
	approx = index;
	approx = approx * DXFEXP;
	result = fexp_value[index];
	result += (x - approx) * fexp_deriv[index];

	return(result);
}
