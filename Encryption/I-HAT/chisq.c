/*
	ChiSqTbl -- Pearson's chi-square test for a 2-way contingency table
 
	last edit:	91/04/01	D A Gwyn
 
	SCCS ID:	@(#)chisq.c	1.3 (export version)
 
	Special	return values:
		-1.0	insufficient degrees of	freedom	(too many 0 entries)
		-2.0	invalid	table entry (frequency less than 0)
		-3.0	invalid	table dimensions (r or c less than 2)
		-4.0	unable to allocate enough working storage
*/
 
#if __STDC__
#include	<stdlib.h>		/* malloc, free	*/
 
#include	"std.h"
#else
#include	"std.h"
 
extern pointer	malloc();
extern void	free();
#endif
 
double
#if __STDC__
ChiSqTbl( int r, int c,	const long *f, int *pdf	)
#else
ChiSqTbl( r, c,	f, pdf )
	int		r;		/* # rows in table */
	int		c;		/* # columns in	table */
	const long	*f;		/* -> r*c frequency tallies */
	int		*pdf;		/* -> return # degrees of freedom */
#endif
	{
#define	x(i,j)	f[(i)*c+(j)]		/* convenient way to access freqs */
	register int	i;		/* row index */
	register int	j;		/* column index	*/
	long		*xi;		/* row sums */
	long		*xj;		/* col sums */
	long		n;		/* total number	of observations	*/
	double		chisq;		/* accumulates chi-square */
	int		rdf = r	- 1;	/* row degrees of freedom */
	int		cdf = c	- 1;	/* column degrees of freedom */
 
	if ( rdf <= 0 || cdf <=	0 )
		{
		chisq =	-3.0;
		goto ret3;
		}
 
	if ( (xi = (long *)malloc( r * sizeof(long) )) == NULL )
		{
		chisq =	-4.0;
		goto ret3;
		}
 
	if ( (xj = (long *)malloc( c * sizeof(long) )) == NULL )
		{
		chisq =	-4.0;
		goto ret2;
		}
 
	/* compute row sums and	total */
 
	n = 0L;
 
	for ( i	= 0; i < r; ++i	)
		{
		long	sum = 0L;	/* accumulator */
 
		for ( j	= 0; j < c; ++j	)
			if ( x(i,j) >= 0L )
				sum += x(i,j);
			else	{
				chisq =	-2.0;
				goto ret1;
				}
 
		if ( (xi[i] = sum) <= 0L )
			--rdf;
		else
			n += sum;
		}
 
	/* compute column sums */
 
	for ( j	= 0; j < c; ++j	)
		{
		long	sum = 0L;	/* accumulator */
 
		for ( i	= 0; i < r; ++i	)
			sum += x(i,j);
 
		if ( (xj[j] = sum) <= 0L )
			--cdf;
		}
 
	if ( rdf <= 0 || cdf <=	0 )
		{
		chisq =	-1.0;
		goto ret1;
		}
 
	*pdf = rdf * cdf;		/* total degrees of freedom */
 
	/* compute chi-square */
 
	chisq =	0.0;
 
	for ( i	= 0; i < r; ++i	)
		if ( xi[i] > 0L	)
			{
			register double	xii = (double)xi[i];
 
			for ( j	= 0; j < c; ++j	)
				if ( xj[j] > 0L	)
					{
					double	expected =
						xii * (double)xj[j] / n;
					double	delta =
						(double)x(i,j) - expected;
 
					chisq += delta * delta / expected;
					}
			}
 
    ret1:
	free( (pointer)xj );
    ret2:
	free( (pointer)xi );
    ret3:
	return chisq;
	}
