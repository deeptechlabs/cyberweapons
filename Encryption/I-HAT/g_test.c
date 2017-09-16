/*
	g_test -- tests	for gamma and related functions
 
	last edit:	91/04/01	D A Gwyn
 
	SCCS ID:	@(#)g_test.c	1.2 (export version)
*/
 
#include	<stdio.h>
#if __STDC__
#include	<stdlib.h>
#else
extern void	exit();
#endif
 
#include	"std.h"
#include	"gamma.h"
 
#define	Print	(void)printf
 
#define	TOL	1.0e-5			/* tolerance for checks	*/
 
static bool	errs = false;		/* set if any test fails */
 
static double
RelDif(	a, b )			/* returns relative difference:	*/
	double	a, b;		/* 0.0 if exactly the same,
				   otherwise ratio of difference
				   to the larger of the	two	*/
	{
	double	c = Abs( a );
	double	d = Abs( b );
 
	d = Max( c, d );
 
	return d == 0.0	? 0.0 :	Abs( a - b ) / d;
	}
 
static void
RCheck(	d, r )				/* check real number */
	double	d;			/* real	to be checked */
	double	r;			/* expected value */
	{
	if ( RelDif( d,	r ) > TOL )
		{
		errs = true;
		Print( "value s.b. %g, was %g\n", r, d );
		}
	}
 
void
GTest()
	{
	static struct
		{
		double	in;			/* input values	*/
		double	exp;			/* expected output values */
		}	tbl[] =			/* table of test values	*/
		{
		{	1.0,		1.0			},
		{	2.0,		1.0			},
		{	3.0,		2.0			},
		{	4.0,		6.0			},
		{	5.0,		24.0			},
		{	6.0,		120.0			},
		{	0.5,		1.7724538509		},
		{	1.5,		0.8862269255		},
		{	0.25,		3.6256099082		},
		{	0.333333333333,	2.6789385347		},
		{	0.666666666667,	1.3541179394		},
		{	0.75,		1.2254167024		},
		{	10.0,		362880.0		},
		{	20.0,		1.2164510041e+17	},
		};
	register int	i;		/* indexes tbl[] test values */
 
	for ( i	= 0; i < Elements( tbl ); ++i )
		RCheck(	Gamma( tbl[i].in ), tbl[i].exp );
	}
 
void
FTest()
	{
	static struct
		{
		int	in;			/* input values	*/
		double	exp;			/* expected output values */
		}	tbl[] =			/* table of test values	*/
		{
		{	0,		1.0			},
		{	1,		1.0			},
		{	2,		2.0			},
		{	3,		6.0			},
		{	4,		24.0			},
		{	5,		120.0			},
		{	6,		720.0			},
		{	10,		3628800.0		},
		{	20,		2.4329020082e+18	},
		};
	register int	i;		/* indexes tbl[] test values */
 
	for ( i	= 0; i < Elements( tbl ); ++i )
		RCheck(	Factorial( tbl[i].in ),	tbl[i].exp );
	}
 
void
BCTest()
	{
	static struct
		{
		int	n;			/* top parts of	inputs */
		int	k;			/* bottom parts	of inputs */
		double	exp;			/* expected output values */
		}	tbl[] =			/* table of test values	*/
		{
		{	1,		0,		1.0		},
		{	1,		1,		1.0		},
		{	2,		0,		1.0		},
		{	2,		1,		2.0		},
		{	2,		2,		1.0		},
		{	3,		0,		1.0		},
		{	3,		1,		3.0		},
		{	3,		2,		3.0		},
		{	5,		3,		10.0		},
		{	10,		4,		210.0		},
		{	10,		5,		252.0		},
		{	40,		6,		3838380.0	},
		{	50,		20,		47129212243960.0},
		};
	register int	i;		/* indexes tbl[] test values */
 
	for ( i	= 0; i < Elements( tbl ); ++i )
		RCheck(	BCoeff(	tbl[i].n, tbl[i].k ), tbl[i].exp );
	}
 
void
ETest()
	{
	static struct
		{
		double	in;			/* input values	*/
		double	exp;			/* expected output values */
		}	tbl[] =			/* table of test values	*/
		{
		{	0.0,		0.0			},
		{	0.1,		0.1124629160		},
		{	0.2,		0.2227025892		},
		{	0.5,		0.5204998778		},
		{	0.8,		0.7421009647		},
		{	1.0,		0.8427007929		},
		{	1.5,		0.9661051465		},
		{	2.0,		0.9953222650		},
		};
	register int	i;		/* indexes tbl[] test values */
 
	for ( i	= 0; i < Elements( tbl ); ++i )
		RCheck(	Erf( tbl[i].in ), tbl[i].exp );
	}
 
void
QCTest()
	{
	static struct
		{
		double	chisq;			/* chi-square limit */
		int	df;			/* degrees of freedom */
		double	exp;			/* expected output values */
		}	tbl[] =			/* table of test values	*/
		{
		{	0.001,		1,		0.97477		},
		{	0.01,		1,		0.92034		},
		{	0.01,		2,		0.99501		},
		{	0.05,		1,		0.82306		},
		{	0.1,		1,		0.75183		},
		{	0.1,		2,		0.95123		},
		{	1.0,		1,		0.31731		},
		{	1.0,		2,		0.60653		},
		{	1.0,		3,		0.80125		},
		{	1.0,		4,		0.90980		},
		{	1.0,		5,		0.96257		},
		{	1.5,		2,		0.47237		},
		{	2.0,		1,		0.15730		},
		{	2.0,		3,		0.57241		},
		{	2.0,	   	5,		0.84915		},
		{	4.0,		6,		0.67668		},
		{	5.0,		5,		0.41588		},
		{	10.0,		7,		0.188573	},
		{	10.0,		10,		0.44049		},
		{	10.0,		20,		0.96817		},
		{	20.0,		30,		0.91654		},
		{	40.0,		30,		0.104864	},
		{	8.26040,	20,		0.99		},
		{	10.8508,	20,		0.95		},
		{	12.4426,	20,		0.90		},
		{	15.4518,	20,		0.75		},
		{	19.3374,	20,		0.50		},
		{	23.8277,	20,		0.25		},
		{	28.4120,	20,		0.10		},
		{	31.4104,	20,		0.05		},
		{	37.5662,	20,		0.01		},
		};
	register int	i;		/* indexes tbl[] test values */
 
	for ( i	= 0; i < Elements( tbl ); ++i )
		RCheck(	QChiSq(	tbl[i].chisq, tbl[i].df	), tbl[i].exp );
	}
 
/*ARGSUSED*/
main( argc, argv )
	int	argc;
	char	*argv[];
	{
	GTest();
	FTest();
	BCTest();
	ETest();
	QCTest();
 
	if ( errs )
		{
		Print( "*** Gamma tests	failed!\n" );
		exit( EXIT_FAILURE );
		}
 
	return EXIT_SUCCESS;
	}
