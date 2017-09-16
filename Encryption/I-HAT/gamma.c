/*
	Gamma -- gamma and related functions
 
	last edit:	91/04/01	D A Gwyn
 
	SCCS ID:	@(#)gamma.c	1.2 (export version)
 
Acknowledgement:
	Code based on that found in "Numerical Methods in C".
*/
 
#include	<assert.h>
#include	<math.h>
 
#include	"std.h"
#include	"gamma.h"	/* not actually	necessary */
 
double
#if __STDC__
LGamma(	double x )
#else
LGamma(	x )
	double			x;
#endif
	{
	static const double   	cof[6] =
		{
		76.18009173,	-86.50532033,	24.01409822,
		-1.231739516,	0.120858003e-2,	-0.536382e-5
		};
	double			tmp, ser;
	register int		j;
 
	assert(x > 0.0);
 
	if ( --x < 0.0 )	/* use reflection formula for accuracy */
		{
		double	pix = PI * x;
 
		return log( pix	/ sin( pix ) ) - LGamma( 1.0 - x );
		}
 
	tmp = x	+ 5.5;
	tmp -= (x + 0.5) * log(	tmp );
 
	ser = 1.0;
 
	for ( j	= 0; j < Elements( cof ); ++j )
		ser += cof[j] /	++x;
 
	return -tmp + log( 2.50662827465 * ser );
	}
 
double
#if __STDC__
Gamma( double x	)
#else
Gamma( x )
	double	x;
#endif
	{
	return exp( LGamma( x )	);
	}
 
double
#if __STDC__
Factorial( register int	n )
#else
Factorial( n )
	register int	n;
#endif
	{
	static double	a[33] =
		{
		1.0,	1.0,	2.0,	6.0,	24.0
		};
	static int	ntop = 4;
 
	assert(n >= 0);
 
	if ( n >= Elements( a )	)
		return Gamma( (double)n	+ 1.0 );
 
	while (	ntop < n )
		{
		register int	j = ntop++;
 
		a[ntop]	= a[j] * (double)ntop;
		}
 
	return a[n];
	}
 
double
#if __STDC__
LFactorial( register int n )
#else
LFactorial( n )
	register int	n;
#endif
	{
	static double	a[99] =	{ 0.0 };
 
	assert(n >= 0);
 
	if ( n <= 1 )
		return 0.0;
	else if	( n <= Elements( a ) + 1 )
		if ( a[n - 2] >	0.0 )	/* table value already set up */
			return a[n - 2];
		else			/* remember for	next time */
			return a[n - 2]	= LGamma( (double)n + 1.0 );
	else				/* beyond range	of table */
		return LGamma( (double)n + 1.0 );
	}
 
double
#if __STDC__
BCoeff(	register int n,	register int k )
#else
BCoeff(	n, k )
	register int	n, k;
#endif
	{
	assert(k >= 0);
	assert(n >= k);
 
	return Round( exp( LFactorial( n )
			 - (LFactorial(	k ) + LFactorial( n - k	))
			 )
		    );
	}
 
double
#if __STDC__
Beta( double z,	double w )
#else
Beta( z, w )
	double	z, w;
#endif
	{
	return exp( LGamma( z )	+ LGamma( w ) -	LGamma(	z + w )	);
	}
 
#define	ITMAX	100
#define	EPS	3.0e-7
 
static double
#if __STDC__
gser( double a,	double x )
#else
gser( a, x )
	double		a, x;
#endif
	{
	double		ap, del, sum;
	register int	n;
 
	assert(x >= 0.0);
 
	if ( x <= 0.0 )
		return 0.0;
 
	del = sum = 1.0	/ (ap =	a);
 
	for ( n	= 1; n <= ITMAX; ++n )
		{
		sum += del *= x	/ ++ap;
 
		if ( Abs( del )	< Abs( sum ) * EPS )
			return sum * exp( -x + a * log(	x ) - LGamma( a	) );
		}
 
	assert(n <= ITMAX);
	/*NOTREACHED*/
	}
 
static double
#if __STDC__
gcf( double a, double x	)
#else
gcf( a,	x )
	double		a, x;
#endif
	{
	register int	n;
	double		gold = 0.0, fac	= 1.0, b1 = 1.0,
			b0 = 0.0, a0 = 1.0, a1 = x;
 
	for ( n	= 1; n <= ITMAX; ++n )
		{
		double	anf;
		double	an = (double)n;
		double	ana = an - a;
 
		a0 = (a1 + a0 *	ana) * fac;
		b0 = (b1 + b0 *	ana) * fac;
		anf = an * fac;
		b1 = x * b0 + anf * b1;
		a1 = x * a0 + anf * a1;
 
		if ( a1	!= 0.0 )
			{		/* renormalize */
			double	g = b1 * (fac =	1.0 / a1);
 
			gold = g - gold;
 
			if ( Abs( gold ) < EPS * Abs( g	) )
				return exp( -x + a * log( x ) -	LGamma(	a ) )
					* g;
 
			gold = g;
			}
		}
 
	assert(n <= ITMAX);
	/*NOTREACHED*/
	}
 
double
#if __STDC__
PGamma(	double a, double x )
#else
PGamma(	a, x )
	double	a, x;
#endif
	{
	assert(x >= 0.0);
	assert(a > 0.0);
 
	return x < a + 1.0 ? gser( a, x	) : 1.0	- gcf( a, x );
	}
 
double
#if __STDC__
QGamma(	double a, double x )
#else
QGamma(	a, x )
	double	a, x;
#endif
	{
	assert(x >= 0.0);
	assert(a > 0.0);
 
	return x < a + 1.0 ? 1.0 - gser( a, x )	: gcf( a, x );
	}
 
double
#if __STDC__
Erf( double x )
#else
Erf( x )
	double	x;
#endif
	{
	return x < 0.0 ? -PGamma( 0.5, x * x ) : PGamma( 0.5, x	* x );
	}
 
double
#if __STDC__
Erfc( double x )
#else
Erfc( x	)
	double	x;
#endif
	{
	return x < 0.0 ? 1.0 + PGamma( 0.5, x *	x ) : QGamma( 0.5, x * x );
	}
 
double
#if __STDC__
CPoisson( double x, int	k )
#else
CPoisson( x, k )
	double	x;
	int	k;
#endif
	{
	return QGamma( (double)k, x );
	}
 
double
#if __STDC__
PChiSq(	double chisq, int df )
#else
PChiSq(	chisq, df )
	double	chisq;
	int	df;
#endif
	{
	return PGamma( (double)df / 2.0, chisq / 2.0 );
	}
 
double
#if __STDC__
QChiSq(	double chisq, int df )
#else
QChiSq(	chisq, df )
	double	chisq;
	int	df;
#endif
	{
	return QGamma( (double)df / 2.0, chisq / 2.0 );
	}
