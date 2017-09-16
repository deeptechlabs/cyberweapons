/*
	<gamma.h> -- definitions for gamma-function routines
 
	last edit:	91/04/01	D A Gwyn
 
	SCCS ID:	@(#)gamma.h	1.2
*/
 
/* library routines: */
 
#if __STDC__
extern double	LGamma(	double x );
extern double	Gamma( double x	);
extern double	Factorial( int n );
extern double	LFactorial( int	n );
extern double	BCoeff(	int n, int k );
extern double	Beta( double z,	double w );
extern double	PGamma(	double a, double x );
extern double	QGamma(	double a, double x );
extern double	Erf( double x );
extern double	Erfc( double x );
extern double	CPoisson( double x, int	k );
extern double	PChiSq(	double chisq, int df );
extern double	QChiSq(	double chisq, int df );
#else
extern double	Gamma();
extern double	LGamma();
extern double	Factorial();
extern double	LFactorial();
extern double	BCoeff();
extern double	Beta();
extern double	PGamma();
extern double	QGamma();
extern double	Erf();
extern double	Erfc();
extern double	CPoisson();
extern double	PChiSq();
extern double	QChiSq();
#endif
