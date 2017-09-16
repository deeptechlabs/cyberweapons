#include	"des.h"
#include	"local_def.h"
#include	"version.h"

/*
 * This software may be freely distributed an modified without any restrictions
 * from the author.
 *
 * This file contains parts from the implementation made by Eric Young
 * <eay@surf.sics.bu.oz.au>, see the copyright information below.
 *
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
 * Comments from the top of the quad_cksum routine in the MIT implementation
 * of DES_CRYPT(3).
 * According to a former student at MIT their implementation does not
 * implement what the comment states, mostly because of broken carry
 * arithmetic.
 * quad_cksum routine will not be included in the version 5 of Kerberos.
 *
 * My thanks to John T Kohl for sending me this information.
 *
 */

/*
 *****************************************************************************
 *
 * Quadratic Congruential Manipulation Dectection Code
 *
 * ref: "Message Authentication"
 *		R.R. Jueneman, S. M. Matyas, C.H. Meyer
 *		IEEE Communications Magazine,
 *		Sept 1985 Vol 23 No 9 p 29-40
 *
 * This routine, part of the Athena DES library built for the Kerberos
 * authentication system, calculates a manipulation detection code for
 * a message.  It is a much faster alternative to the DES-checksum
 * method. No guarantees are offered for its security.	Refer to the
 * paper noted above for more information
 *
 * Implementation for 4.2bsd
 * by S.P. Miller	Project Athena/MIT
 */

/*
 * Algorithm (per paper):
 *		define:
 *		message to be composed of n m-bit blocks X1,...,Xn
 *		optional secret seed S in block X1
 *		MDC in block Xn+1
 *		prime modulus N
 *		accumulator Z
 *		initial (secret) value of accumulator C
 *		N, C, and S are known at both ends
 *		C and , optionally, S, are hidden from the end users
 *		then
 *			(read array references as subscripts over time)
 *			Z[0] = c;
 *			for i = 1...n
 *				Z[i] = (Z[i+1] + X[i])**2 modulo N
 *			X[n+1] = Z[n] = MDC
 *
 *		Then pick
 *			N = 2**31 -1
 *			m = 16
 *			iterate 4 times over plaintext, also use Zn
 *			from iteration j as seed for iteration j+1,
 *			total MDC is then a 128 bit array of the four
 *			Zn;
 *
 *			return the last Zn and optionally, all
 *			four as output args.
 *
 * Modifications:
 *	To inhibit brute force searches of the seed space, this
 *	implementation is modified to have
 *	Z	= 64 bit accumulator
 *	C	= 64 bit C seed
 *	N	= 2**63 - 1
 *  S	= S seed is not implemented here
 *	arithmetic is not quite real double integer precision, since we
 *	cant get at the carry or high order results from multiply,
 *	but nontheless is 64 bit arithmetic.
 *
 ******************************************************************************
 */

/*
#define UNBROKEN_ARITHMETIC
*/

#ifdef UNBROKEN_ARITHMETIC
/*
 * This routine implements the algorithm described above without broken
 * arithmetic (this statment has not been proven :-).
 *
 *						     _
 *						Stig Ostholm
 */
#else  /* UNBROKEN_ARITHMETIC */
/*
 * This part is based on the implementation by Eric Young
 * <eay@surf.sics.bu.oz.au>.
 */
/*
 * Copyright 1990 Eric Young. All Rights Reserved.
 * 
 * This is a DES implementation written by Eric Young (eay@surf.sics.bu.oz.au)
 * The implementation was written so as to conform with the manual entry
 * for the des_crypt(3) library routines from MIT's project Athena.
 * 
 * At this time you may use this library for non-commercial use.
 * If you modify any of the files making up this library, you must
 * add a comment in the modified file indicating who modified it.
 * For commercial purposes please contact me (or Bond Uni via
 * postmaster@surf.sics.bu.oz.au).
 * 
 * If you find bugs or otherwise modify this program, please send
 * changes back to me.
 */

# define NOISE 83653421

#endif /* UNBROKEN_ARITHMETIC */



unsigned long	quad_cksum(
#ifdef __STDC__
	des_cblock	*input,
	des_cblock	*output,
	int		length,
	int		out_count,
	des_cblock	*seed)
#else
	input, output, length, out_count, seed)
des_cblock	*input;
des_cblock	*output;
int		length;
int		out_count;
des_cblock	*seed;
#endif
{
	register int		i;
	register unsigned long	x;
	register unsigned char	*c, *xp, *out;
#ifdef UNBROKEN_ARITHMETIC
# if UNSIGNED_LONG_BITS >= 64
	register unsigned long	z;
# else
	register unsigned long	zl, zh;
	register unsigned long	zl0, z_0_15, z_16_31, t_0_31, t_16_47, t_32_63;
# endif
#else  /* UNBROKEN_ARITHMETIC */
	register unsigned long	zl, zh;
#endif /* UNBROKEN_ARITHMETIC */


	/* Max four iterations. */
	if (output) {
		if (out_count > 4)
			out_count = 4;
	} else
		out_count = 1;
		

	c = *seed;
#if defined(UNBROKEN_ARITHMETIC) && (UNSIGNED_LONG_BITS >= 64)
	/* Z[0] = C */
	z = (unsigned long) *c;
	while (c > (*seed)) {
		z <<= UNSIGNED_CHAR_BITS;
		z |= (unsigned long) *--c;
	}
#else
	/* Z[0] = C */
	CHAR_TO_LONG_8(zl, zh, c);
#endif

	out = (unsigned char *) output;

	while (out_count-- > 0) {

		xp = (unsigned char *) input;
		
		for (i = length; i > 0; i -= 2) {
			if (i > 1) {
				x = *xp++;
				x |= (*xp++) << UNSIGNED_CHAR_BITS;
			} else
				x = *xp;

#ifdef UNBROKEN_ARITHMETIC
# if UNSIGNED_LONG_BITS >= 64
			/* Z[i] = Z[i-1] + X[i] */
			z += x;
			/* Z[i] = Z[i] ** 2 */
			z *= z;
			/* Z[i] modulo (2 ** 63 - 1) */
			z %= 0x7fffffffffffffffl;
# else
			/* Z[i] = Z[i-1] + X[i] */
#if UNSIGNED_LONG_BITS > 32
			zl = (zl + x) & 0xffffffffl;
#else
			zl += x;
#endif
			if (zl < x) /* Carry ? */
				zh++;

			/* Z[i] = Z[i] ** 2 */
			zl0 = zl;
			z_0_15 = zl & 0x0000ffffl;
			z_16_31 = (zl >> 16) & 0x0000ffffl;
			t_0_31 = z_0_15 * z_0_15;
			t_16_47 = z_0_15 * z_16_31;
#if UNSIGNED_LONG_BITS > 32
			zl = (t_0_31 + (t_16_47 << 17)) & 0xffffffffl;
#else
			zl = t_0_31 + (t_16_47 << 17);
#endif
			t_32_63 = (z_16_31 * z_16_31) + (t_16_47 >> 15);
			if (zl < t_0_31) /* Carry ? */
				t_32_63++;
			zh = (2 * zh * zl0) + t_32_63;

			/* Z[i] modulo (2 ** 63 - 1) */
			zh %= 0x7fffffffl;
# endif
#else  /* UNBROKEN_ARITHMETIC */
			/* Z[i] = Z[i-1] + X[i] */
			x += zl;

			/* Z[i] = (Z[i] ** 2) modulo (2 ** 63 - 1) */
			zl = ((x * x) + (zh * zh)) % 0x7fffffffl; 
			zh = (x * (zh + NOISE)) % 0x7fffffffl;
#endif /* UNBROKEN_ARITHMETIC */
		}

		if (out) {
#if defined(UNBROKEN_ARITHMETIC) && (UNSIGNED_LONG_BITS >= 64)
			x = z;
#else
			x = zl;
#endif
			*out++ = (unsigned char) x;
			x >>= UNSIGNED_CHAR_BITS;
			*out++ = (unsigned char) x;
			x >>= UNSIGNED_CHAR_BITS;
			*out++ = (unsigned char) x;
			x >>= UNSIGNED_CHAR_BITS;
			*out++ = (unsigned char) x;
		}
	}

#if defined(UNBROKEN_ARITHMETIC) && (UNSIGNED_LONG_BITS >= 64)
	return z & 0xffffffffl;
#else
	return zl;
#endif
}
