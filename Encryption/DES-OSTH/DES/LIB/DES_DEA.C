#include	"des.h"
#include	"local_def.h"
#include	"fips_def.h"
#include	"tab_IP.h"
#include	"tab_IPinv.h"
#include	"tab_E.h"
#include	"tab_S_and_P.h"
#include	"version.h"

/*
 * This software may be freely distributed an modified without any restrictions
 * from the author.
 * Additional restrictions due to national laws governing the use, import or
 * export of cryptographic software is the responsibility of the software user,
 * importer or exporter to follow.
 *
 *					     _
 *					Stig Ostholm
 *					Department of Computer Engineering
 *					Chalmers University of Technology
 */

/*
 * des_dea
 *
 *	The standard data encryption algorithm as described in
 *	FIPS 46 1977 january 15. 
 */

/*
 * The funktion F
 */

#ifdef E_DATA
# ifdef S_AND_P_DATA
#  define F_DATA \
	des_cblock		b; \
	register unsigned char	*ksn; \
	E_DATA; \
	S_AND_P_DATA
# else  /* S_AND_P_DATA */
#  define F_DATA \
	des_cblock		b; \
	register unsigned char	*ksn; \
	E_DATA
# endif /* S_AND_P_DATA */
#else  /* E_DATA */
# ifdef S_AND_P_DATA
#  define F_DATA \
	des_cblock		b; \
	register unsigned char	*ksn; \
	S_AND_P_DATA
# else  /* S_AND_P_DATA */
#  define F_DATA \
	des_cblock		b; \
	register unsigned char	*ksn
# endif /* S_AND_P_DATA */
#endif /* E_DATA */

#define	F(R, KSn)  \
\
	ksn = KSn; \
	E(b, R); \
	XOR_8(b, ksn); \
	R = S_AND_P(b); \

/*
 * One iteration
 */

#ifdef F_DATA
# define ITERATION_DATA \
	register unsigned long	r0; \
	F_DATA
#else  /*  F_DATA */
# define ITERATION_DATA \
	register unsigned long	r0
#endif /*  F_DATA */

#define ITERATION(L, R, KSn) \
\
	r0 = R; \
	F(R, KSn); \
	R ^= L; \
	L = r0


/*
 * des_dea
 *
 *	Base encryption algorithm
 *
 *	`input' and `output' may be overlapping.
 *
 */

/*
#define USE_LOOP
*/

int	des_dea(
#ifdef __STDC__
	des_cblock		*input,
	des_cblock		*output,
	des_key_schedule	schedule,
	int			encrypt)
#else
	input, output, schedule, encrypt)
des_cblock		*input;
des_cblock		*output;
des_key_schedule	schedule;
int			encrypt;
#endif
{
	register unsigned long	l, r;
#ifdef USE_LOOP
	register int		n;
#endif /* USE_LOOP */
#ifdef IP_DATA
	IP_DATA;
#endif /* IP_DATA */
#ifdef ITERATION_DATA
	ITERATION_DATA;
#endif /* ITERATION_DATA */
#ifdef IPinv_DATA
	IPinv_DATA;
#endif /* IPinv_DATA */


	/* IP - Initial Permutaion */
	IP(l, r, (*input));

	/* I 1 .. DES_ITERATIONS - Iterations */
	if (encrypt) {
#ifdef USE_LOOP
		for (n = 0; n < DES_ITERATIONS; n++) {
			ITERATION(l, r, schedule[n]._);
		}
#else  /* USE_LOOP */
		ITERATION(l, r, schedule[0]._);
		ITERATION(l, r, schedule[1]._);
		ITERATION(l, r, schedule[2]._);
		ITERATION(l, r, schedule[3]._);
		ITERATION(l, r, schedule[4]._);
		ITERATION(l, r, schedule[5]._);
		ITERATION(l, r, schedule[6]._);
		ITERATION(l, r, schedule[7]._);
		ITERATION(l, r, schedule[8]._);
		ITERATION(l, r, schedule[9]._);
		ITERATION(l, r, schedule[10]._);
		ITERATION(l, r, schedule[11]._);
		ITERATION(l, r, schedule[12]._);
		ITERATION(l, r, schedule[13]._);
		ITERATION(l, r, schedule[14]._);
		ITERATION(l, r, schedule[15]._);
#endif /* USE_LOOP */
	} else {
#ifdef USE_LOOP
		for (n = DES_ITERATIONS - 1; n >= 0; n--) {
			ITERATION(l, r, schedule[n]._);
		}
#else  /* USE_LOOP */
		ITERATION(l, r, schedule[15]._);
		ITERATION(l, r, schedule[14]._);
		ITERATION(l, r, schedule[13]._);
		ITERATION(l, r, schedule[12]._);
		ITERATION(l, r, schedule[11]._);
		ITERATION(l, r, schedule[10]._);
		ITERATION(l, r, schedule[9]._);
		ITERATION(l, r, schedule[8]._);
		ITERATION(l, r, schedule[7]._);
		ITERATION(l, r, schedule[6]._);
		ITERATION(l, r, schedule[5]._);
		ITERATION(l, r, schedule[4]._);
		ITERATION(l, r, schedule[3]._);
		ITERATION(l, r, schedule[2]._);
		ITERATION(l, r, schedule[1]._);
		ITERATION(l, r, schedule[0]._);
#endif /* USE_LOOP */
	}

	/* IPinv - Inverse of Initial Permutaion IP */
	IPinv((*output), r, l);

	return 0;
}
