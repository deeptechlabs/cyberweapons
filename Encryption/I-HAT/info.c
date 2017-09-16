/*
	InfoTbl	-- Kullback's information measure for a	2-way contingency table
 
	last edit:	91/04/01	D A Gwyn
 
	SCCS ID:	@(#)info.c	1.2 (export version)
 
	Special	return values:
		-1.0	entire table consisted of 0 entries
		-2.0	invalid	table entry (frequency less than 0)
		-3.0	invalid	table dimensions (r or c less than 2)
		-4.0	unable to allocate enough working storage
*/
 
#include	<math.h>		/* for log() */
#if __STDC__
#include	<stdlib.h>		/* malloc, free	*/
 
#include	"std.h"
#else
#include	"std.h"
 
extern pointer	malloc();
extern void	free();
#endif
 
#ifndef	MAXFASTN
#define	MAXFASTN	1000		/* largest "fast" value	of n */
#endif
 
static double
#if __STDC__
NLogN( register	long n )
#else
NLogN( n )				/* returns n*log(n), quickly */
	register long	n;
#endif
	{
	static double	nln[MAXFASTN - 1] = { 0.0 };	/* known values	*/
 
	if ( n <= 1L )
		return 0.0;
	else if	( n <= (long)(Elements(	nln ) +	1) )
		{
		register int	nm2 = (int)n - 2;
 
		if ( nln[nm2] >	0.0 )	/* table value already set up */
			return nln[nm2];
		else	{		/* remember for	next time */
			register double	dn = (double)n;
 
			return nln[nm2]	= dn * log( dn );
			}
		}
	else	{			/* beyond range	of table */
		register double	dn = (double)n;
 
		return dn * log( dn );
		}
	}
 
double
#if __STDC__
InfoTbl( int r,	int c, const long *f, int *pdf )
#else
InfoTbl( r, c, f, pdf )			/* returns twice the MDI */
	int		r;		/* # rows in table */
	int		c;		/* # columns in	table */
	const long	*f;		/* -> r*c frequency tallies */
	int		*pdf;		/* -> return # d.f. for	chi-square */
#endif
	{
#define	x(i,j)	f[(i)*c+(j)]		/* convenient way to access freqs */
	register int	i;		/* row index */
	register int	j;		/* column index	*/
	long		*xi;		/* row sums */
	long		*xj;		/* col sums */
	long		n;		/* total number	of observations	*/
	double		info;		/* accumulates information measure */
	int		rdf = r	- 1;	/* row degrees of freedom */
	int		cdf = c	- 1;	/* column degrees of freedom */
 
	if ( rdf <= 0 || cdf <=	0 )
		{
		info = -3.0;
		goto ret3;
		}
 
	*pdf = rdf * cdf;		/* total degrees of freedom */
 
	if ( (xi = (long *)malloc( r * sizeof(long) )) == NULL )
		{
		info = -4.0;
		goto ret3;
		}
 
	if ( (xj = (long *)malloc( c * sizeof(long) )) == NULL )
		{
		info = -4.0;
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
				info = -2.0;
				goto ret1;
				}
 
		n += xi[i] = sum;
		}
 
	if ( n <= 0L )
		{
		info = -1.0;
		goto ret1;
		}
 
	/* compute column sums */
 
	for ( j	= 0; j < c; ++j	)
		{
		long	sum = 0L;	/* accumulator */
 
		for ( i	= 0; i < r; ++i	)
			sum += x(i,j);
 
		xj[j] =	sum;
		}
 
	/* compute information measure (four parts) */
 
	info = NLogN( n	);					/* part	1 */
 
	for ( i	= 0; i < r; ++i	)
		{
		if ( xi[i] > 0L	)
			info -=	NLogN( xi[i] );			/* part	2 */
 
		for ( j	= 0; j < c; ++j	)
			if ( x(i,j) > 0L )
				info +=	NLogN( x(i,j) );	/* part	3 */
		}
 
	for ( j	= 0; j < c; ++j	)
		if ( xj[j] > 0L	)
			info -=	NLogN( xj[j] );			/* part	4 */
 
	info *=	2.0;			/* for comparability with chi-square */
 
    ret1:
	free( (pointer)xj );
    ret2:
	free( (pointer)xi );
    ret3:
	return info;
	}
END OF info.c
echo 'std.h' 1>&2
cat >'std.h' <<'END OF std.h'
/*
	std.h -- Douglas A. Gwyn's standard C programming definitions
 
	Prerequisites:	<math.h> (if you invoke	Round())
			<string.h> (if you invoke StrEq())
 
	last edit:	90/11/17	D A Gwyn
 
	SCCS ID:	@(#)std.h	1.37
 
	The master source file is to be	modified only by Douglas A. Gwyn
	<Gwyn@BRL.MIL>.	 When installing a VLD/VMB software distribution,
	this file may need to be tailored slightly to fit the target system.
	Usually	this just involves enabling some of the	"kludges for deficient
	C implementations" at the end of this file.
*/
 
#ifndef	VLD_STD_H_
#define	VLD_STD_H_			/* once-only latch */
 
/* Extended data types */
 
typedef	int	bool;			/* Boolean data	*/
#define		false	0
#define		true	1
 
typedef	int	bs_type;		/* 3-way "bug/status" result type */
#define		bs_good	1
#define		bs_bad	0
#define		bs_ugly	(-1)
 
/* ANSI	C definitions */
 
/* Defense against some	silly systems defining __STDC__	to random things. */
#ifdef STD_C
#undef STD_C
#endif
#ifdef __STDC__
#if __STDC__ > 0
#define	STD_C	__STDC__		/* use this instead of __STDC__	*/
#endif
#endif
 
#ifdef STD_C
typedef	void	*pointer;		/* generic pointer */
#else
typedef	char	*pointer;		/* generic pointer */
#define	const		/* nothing */	/* ANSI	C type qualifier */
/* There really	is no substitute for the following, but	these might work: */
#define	signed		/* nothing */	/* ANSI	C type specifier */
#define	volatile	/* nothing */	/* ANSI	C type qualifier */
#endif
 
#ifndef	EXIT_SUCCESS
#define	EXIT_SUCCESS	0
#endif
 
#ifndef	EXIT_FAILURE
#define	EXIT_FAILURE	1
#endif
 
#ifndef	NULL
#define	NULL	0			/* null	pointer	constant, all types */
#endif
 
/* Universal constants */
 
#define	DEGRAD	57.2957795130823208767981548141051703324054724665642
					/* degrees per radian */
#define	E	2.71828182845904523536028747135266249775724709369996
					/* base	of natural logs	*/
#define	GAMMA	0.57721566490153286061
					/* Euler's constant */
#define	LOG10E	0.43429448190325182765112891891660508229439700580367
					/* log of e to the base	10 */
#define	PHI	1.618033988749894848204586834365638117720309180
					/* golden ratio	*/
#define	PI	3.14159265358979323846264338327950288419716939937511
					/* ratio of circumf. to	diam. */
 
/* Useful macros */
 
/*
	The comment "UNSAFE" means that	the macro argument(s) may be evaluated
	more than once,	so the programmer must realize that the	macro doesn't
	quite act like a genuine function.  This matters only when evaluating
	an argument produces "side effects".
*/
 
/* arbitrary numerical arguments and value: */
#define	Abs( x )	((x) < 0 ? -(x)	: (x))			/* UNSAFE */
#define	Max( a,	b )	((a) > (b) ? (a) : (b))			/* UNSAFE */
#define	Min( a,	b )	((a) < (b) ? (a) : (b))			/* UNSAFE */
 
/* floating-point arguments and	value: */
#define	Round( d )	floor( (d) + 0.5 )		/* requires <math.h> */
 
/* arbitrary numerical arguments, integer value: */
#define	Sgn( x )	((x) ==	0 ? 0 :	(x) > 0	? 1 : -1)	/* UNSAFE */
 
/* string arguments, boolean value: */
#ifdef gould	/* UTX-32 2.0 compiler has problems with "..."[] */
#define	StrEq( a, b )	(strcmp( a, b )	== 0)
#else
#define	StrEq( a, b )	(*(a) == *(b) && strcmp( a, b )	== 0)	/* UNSAFE */
#endif
 
/* array argument, integer value: */
#define	Elements( a )	(sizeof	a / sizeof a[0])
 
/* integer (or character) arguments and	value: */
#define	fromhostc( c )	(c)		/* map host char set to	ASCII */
#define	tohostc( c )	(c)		/* map ASCII to	host char set */
#define	tonumber( c )	((c) - '0')	/* convt digit char to number */
#define	todigit( n )	((n) + '0')	/* convt digit number to char */
 
/* to permit a single declaration to provide a prototype or not, depending: */
/* Example usage:	extern int myfunc PARAMS((int a, char *b));	*/
#ifdef STD_C
#define	PARAMS(	a )	a
#else
#define	PARAMS(	a )	()
#endif
 
/* weird macros	for special tricks with	source code symbols: */
#ifdef STD_C
#define	PASTE( a, b )	a ## b
					/* paste together two token strings */
#define	STRINGIZE( s )	# s
					/* convert tokens to string literal */
#else
/* Q8JOIN is for internal <std.h> use only: */
#define	Q8JOIN(	s )	s
#define	PASTE( a, b )	Q8JOIN(a)b
					/* paste together two token strings */
	/* WARNING:  This version of PASTE may expand its arguments
	   before pasting, unlike the Standard C version. */
#define	STRINGIZE( s )	"s"		/* (Reiser cpp behavior	assumed) */
					/* convert tokens to string literal */
	/* WARNING:  This version of STRINGIZE does not	properly handle	" and
	   \ characters	in character-constant and string-literal tokens. */
#endif
 
/* Kludges for deficient C implementations */
 
/*#define 	strchr	index		/* 7th Edition UNIX, 4.2BSD */
/*#define	strrchr	rindex		/* 7th Edition UNIX, 4.2BSD */
/*#define	void	int		/* K&R Appendix	A followers */
 
#if defined(sgi) && defined(mips)	/* missing from	<signal.h>: */
extern void	(*signal(int, void (*)(int)))(int);
#endif
 
#endif	/* VLD_STD_H_ */
END OF std.h
echo 'tot_info.1' 1>&2
cat >'tot_info.1' <<'END OF tot_info.1'
'\" e
.TH TOT_INFO 1V	VMB
'\"	last edit:	91/04/01	D A Gwyn
'\"	SCCS ID:	@(#)tot_info.1	1.3
.EQ
delim @@
.EN
.SH NAME
tot_info \- total information for multiple 2-way contingency tables
.SH SYNOPSIS
.ds cW (CW\" change to I (without the paren) if	you don't have a CW font
.ds cB (CB\" change to B (without the paren) if	you don't have a CB font
\f\*(cBtot_info\fP
.SH DESCRIPTION
\f\*(cBtot_info\fP
reads multiple contingency-table data sets from	the standard input
and prints Kullback's information statistic for	each set,
as well	as for the aggregate over all sets,
on the standard	output.
(See \fIchisq\^\fP(3V) for a discussion	of this	statistic.)
.SH "INPUT FORMAT"
Input consists of one or more data sets,
each constituting a 2-way contingency table
(not necessarily all of	the same size).
A data set may be preceded by any number of blank or comment lines;
a comment line has a
\f\*(cB#\fP
character as the first non-whitespace character	on the line.
Following the optional comment lines is	a header line
containing the row and column dimensions of the	contingency table
(in that order),
separated by white space.
Finally, the contents of the contingency table (frequency counts)
must be	given in ``row major'' order.
The table may be freely	formatted with white-space separators;
a row need not be on a single line.
.SH "OUTPUT FORMAT"
Input comments are copied to the output	as they	are encountered.
Otherwise the output consists solely of	an information line for
each data set (or a diagnostic if the data is invalid) and a final
information line for the aggregate over	all data sets (preceded	by
a blank	line).
An information line exhibits twice the value of	Kullback's
@"\v'-0.2'^\v'0.2'\h'-\w;^;u'I\^" ( H sub 1 : H	sub 2 )@ statistic,
the corresponding number of degrees of freedom,
and the	probability that the statistic
would be as large as was actually observed
if the row and column categorizations really were independent.
.P
The aggregate statistic	is valid if the	data sets
represent independent tests of the same	hypothesis.
.SH DIAGNOSTICS
The diagnostic messages	are intended to	be self-explanatory.
.SH "EXIT STATUS"
\f\*(cBtot_info\fP
returns	a zero exit status if and only if no problems were encountered.
.SH EXAMPLE
.RS
\f\*(cB
.ta 8n 16n 24n 32n 40n 48n 56n 64n
.nf
$ \fP\f\*(cWtot_info
\&
# MilCrypI.60 biliteral	cryptogram (trial pairings against G)
# G vs B
2 10
2 2 2 0	3 0 0 1	0 1
3 1 1 1	1 2 2 1	2 1
# G vs D
2 10
2 2 2 0	3 0 0 1	0 1
4 1 4 4	1 1 1 3	4 2
# G vs J
2 10
2 2 2 0	3 0 0 1	0 1
1 1 1 1	1 1 2 1	1 1
# G vs L
2 10
2 2 2 0	3 0 0 1	0 1
1 4 0 4	3 4 5 3	3 4
# G vs N
2 10
2 2 2 0	3 0 0 1	0 1
4 1 4 3	1 1 1 2	3 3
# G vs Q
2 10
2 2 2 0	3 0 0 1	0 1
0 2 0 2	1 1 1 0	1 0
# G vs S (correct pairing)
2 10
2 2 2 0	3 0 0 1	0 1
1 2 2 0	2 1 0 0	0 1
# G vs V
2 10
2 2 2 0	3 0 0 1	0 1
1 4 1 3	4 4 4 3	4 3
# G vs X
2 10
2 2 2 0	3 0 0 1	0 1
0 1 0 1	2 1 1 0	2 0
# Since	most pairings are incorrect,
# the aggregate	probability is small.
^D\fP\f\*(cB
# MilCrypI.60 biliteral	cryptogram (trial pairings against G)
# G vs B
2info =	11.01	df =  9	q =  0.2748
# G vs D
2info =	12.40	df =  9	q =  0.1915
# G vs J
2info =	 9.00	df =  9	q =  0.4375
# G vs L
2info =	19.03	df =  9	q =  0.0250
# G vs N
2info =	10.89	df =  9	q =  0.2830
# G vs Q
2info =	15.82	df =  9	q =  0.0707
# G vs S (correct pairing)
2info =	 3.11	df =  9	q =  0.9596
# G vs V
2info =	14.47	df =  9	q =  0.1066
# G vs X
2info =	15.31	df =  9	q =  0.0826
# Since	most pairings are incorrect,
# the aggregate	probability is small.
\&
total 2info = 111.05	df = 81	q =  0.0150\fP
.ta .5i	1i 1.5i	2i 2.5i	3i 3.5i
.fi
.RE
.SH REFERENCES
Solomon	Kullback, \fIInformation Theory	and Statistics\fP (Dover, 1968).
.br
William	F.\& Friedman and Lambros D.\& Callimahos,
\fIMilitary Cryptanalytics, Part I \(em	Volume 1\fP
(reprinted by Aegean Park Press, 1985).
.SH "SEE ALSO"
chisq(3V).
.SH AUTHOR
Douglas	A.\& Gwyn, U.S.\& Army BRL/VLD-VMB
END OF tot_info.1
echo 'tot_info.c' 1>&2
cat >'tot_info.c' <<'END OF tot_info.c'
/*
	tot_info -- combine information	statistics for multiple	tables
 
      	last edit:	91/04/01	D A Gwyn
 
	SCCS ID:	@(#)tot_info.c	1.2 (export version)
*/
 
#include	<ctype.h>
#include	<stdio.h>
#if __STDC__
#include	<stdlib.h>
#else
extern void	exit();
#endif
 
#include	"std.h"
 
#include	"chisq.h"
#include	"gamma.h"		/* for QChiSq()	*/
 
#ifndef	MAXLINE
#define	MAXLINE	256
#endif
 
#ifndef	MAXTBL
#define	MAXTBL	1000
#endif
 
#define	Print	(void)printf
#define	Put(s)	(void)fputs( s,	stdout )
 
static char	line[MAXLINE];		/* row/column header input line	*/
static long	f[MAXTBL];		/* frequency tallies */
static int	r;			/* # of	rows */
static int	c;			/* # of	columns	*/
 
#define	x(i,j)	f[(i)*c+(j)]		/* convenient way to access freqs */
 
#define	COMMENT	'#'			/* comment character */
 
/*ARGSUSED*/
int
main( argc, argv )
	int		argc;
	char		*argv[];
	{
	register char	*p;		/* input line scan location */
	register int	i;		/* row index */
	register int	j;		/* column index	*/
	double		info;		/* computed information	measure	*/
	int		infodf;		/* degrees of freedom for information */
	double		totinfo	= 0.0;	/* accumulated information */
	int		totdf =	0;	/* accumulated degrees of freedom */
 
	while (	fgets( line, MAXLINE, stdin ) != NULL )	/* start new table */
		{
		for ( p	= line;	*p != '\0' && isspace( (int)*p ); ++p )
			;
 
		if ( *p	== '\0'	)
			continue;	/* skip	blank line */
 
		if ( *p	== COMMENT )
			{		/* copy	comment	through	*/
			Put( line );
			continue;
			}
 
		if ( sscanf( p,	"%d %d\n", &r, &c ) != 2 )
			{
			Put( "*	invalid	row/column line	*\n" );
			exit( EXIT_FAILURE );
			}
 
		if ( r * c > MAXTBL )
			{
			Put( "*	table too large	*\n" );
			exit( EXIT_FAILURE );
			}
 
		/* input tallies */
 
		for ( i	= 0; i < r; ++i	)
			for ( j	= 0; j < c; ++j	)
				if ( scanf( " %ld", &x(i,j) ) != 1 )
					{
					Put( "*	EOF in table *\n" );
					exit( EXIT_FAILURE );
					}
 
		/* compute statistic */
 
		info = InfoTbl(	r, c, f, &infodf );
 
		/* print results */
 
		if ( info >= 0.0 )
			{
			Print( "2info =	%5.2f\tdf = %2d\tq = %7.4f\n",
			       info, infodf, QChiSq( info, infodf )
			     );
			totinfo	+= info;
			totdf += infodf;
			}
		else if	( info < -3.5 )
			Put( "out of memory\n" );
		else if	( info < -2.5 )
			Put( "table too	small\n" );
		else if	( info < -1.5 )
			Put( "negative freq\n" );
		else if	( info < -0.5 )
			Put( "table all	zeros\n" );
		else			/* "can't happen" */
			Put( "unknown error\n" );
		}
 
	if ( totdf <= 0	)
		{
		Put( "\n*** no information accumulated ***\n" );
		exit( EXIT_FAILURE );
		}
 
	Print( "\ntotal	2info =	%5.2f\tdf = %2d\tq = %7.4f\n",
	       totinfo,	totdf, QChiSq( totinfo,	totdf )
	     );
	return EXIT_SUCCESS;
	}
END OF tot_info.c
echo 'tot_info.exp' 1>&2
cat >'tot_info.exp' <<'END OF tot_info.exp'
# MilCrypI.60 biliteral	cryptogram (trial pairings against G)
# G vs B
2info =	11.01	df =  9	q =  0.2748
# G vs D
2info =	12.40	df =  9	q =  0.1915
# G vs J
2info =	 9.00	df =  9	q =  0.4375
# G vs L
2info =	19.03	df =  9	q =  0.0250
# G vs N
2info =	10.89	df =  9	q =  0.2830
# G vs Q
2info =	15.82	df =  9	q =  0.0707
# G vs S (correct pairing)
2info =	 3.11	df =  9	q =  0.9596
# G vs V
2info =	14.47	df =  9	q =  0.1066
# G vs X
2info =	15.31	df =  9	q =  0.0826
# Since	most pairings are incorrect,
# the aggregate	probability is small.
 
total 2info = 111.05	df = 81	q =  0.0150
END OF tot_info.exp
echo 'tot_info.in' 1>&2
cat >'tot_info.in' <<'END OF tot_info.in'
# MilCrypI.60 biliteral	cryptogram (trial pairings against G)
# G vs B
2 10
2 2 2 0	3 0 0 1	0 1
3 1 1 1	1 2 2 1	2 1
# G vs D
2 10
2 2 2 0	3 0 0 1	0 1
4 1 4 4	1 1 1 3	4 2
# G vs J
2 10
2 2 2 0	3 0 0 1	0 1
1 1 1 1	1 1 2 1	1 1
# G vs L
2 10
2 2 2 0	3 0 0 1	0 1
1 4 0 4	3 4 5 3	3 4
# G vs N
2 10
2 2 2 0	3 0 0 1	0 1
4 1 4 3	1 1 1 2	3 3
# G vs Q
2 10
2 2 2 0	3 0 0 1	0 1
0 2 0 2	1 1 1 0	1 0
# G vs S (correct pairing)
2 10
2 2 2 0	3 0 0 1	0 1
1 2 2 0	2 1 0 0	0 1
# G vs V
2 10
2 2 2 0	3 0 0 1	0 1
1 4 1 3	4 4 4 3	4 3
# G vs X
2 10
2 2 2 0	3 0 0 1	0 1
0 1 0 1	2 1 1 0	2 0
# Since	most pairings are incorrect,
# the aggregate	probability is small.
END OF tot_info.in
 

