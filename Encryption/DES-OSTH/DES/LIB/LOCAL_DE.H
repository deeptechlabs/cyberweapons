#include	"compile.h"

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
 * Macros used in the functions
 */

/*
 * Copy the contentse from `B[0..7]' to `L'`R'.
 */

#if defined(UNSIGNED_LSB_FIRST) && (UNSIGNED_LONG_BITS == 32) && \
	! defined(UNSIGNED_LONG_ALIGN)
# define	CHAR_TO_LONG_8(L, R, B) \
	L = *((unsigned long *) B); \
	R = *((unsigned long *) &B[4])
#else
# if defined(UNSIGNED_LSB_FIRST) && (UNSIGNED_LONG_BITS == 64) && \
	! defined(UNSIGNED_LONG_ALIGN)
#  define	CHAR_TO_LONG_8(L, R, B) \
	L = *((unsigned long *) B) & 0xffffffffl;
	R = *((unsigned long *) &B[4]) & 0xffffffffl;
# else
#  define	CHAR_TO_LONG_8(L, R, B) \
	R = B[7]; \
	R <<= UNSIGNED_CHAR_BITS; \
	R |= B[6]; \
	R <<= UNSIGNED_CHAR_BITS; \
	R |= B[5]; \
	R <<= UNSIGNED_CHAR_BITS; \
	R |= B[4]; \
	L = B[3]; \
	L <<= UNSIGNED_CHAR_BITS; \
	L |= B[2]; \
	L <<= UNSIGNED_CHAR_BITS; \
	L |= B[1]; \
	L <<= UNSIGNED_CHAR_BITS; \
	L |= B[0]
# endif
#endif


/*
 * Copy the contentse from `L'`R' to `B[0..7]'.
 */

#if defined(UNSIGNED_LSB_FIRST) && (UNSIGNED_LONG_BITS == 32) && \
	! defined(UNSIGNED_LONG_ALIGN)
# define	LONG_TO_CHAR_8(B, L, R) \
	*((unsigned long *) B) = L; \
	*((unsigned long *) &B[4]) = R
#else
# if defined(UNSIGNED_LSB_FIRST) && (UNSIGNED_LONG_BITS == 64) && \
	! defined(UNSIGNED_LONG_ALIGN)
#  define	LONG_TO_CHAR_8(B, L, R) \
	*((unsigned long *) B) = L | (R << 32);
# else
#  define	LONG_TO_CHAR_8(B, L, R) \
{ \
	register unsigned long	tmp; \
\
	tmp = L; \
	B[0] = tmp; \
	tmp >>= UNSIGNED_CHAR_BITS; \
	B[1] = tmp; \
	tmp >>= UNSIGNED_CHAR_BITS; \
	B[2] = tmp; \
	tmp >>= UNSIGNED_CHAR_BITS; \
	B[3] = tmp; \
	tmp = R; \
	B[4] = tmp; \
	tmp >>= UNSIGNED_CHAR_BITS; \
	B[5] = tmp; \
	tmp >>= UNSIGNED_CHAR_BITS; \
	B[6] = tmp; \
	tmp >>= UNSIGNED_CHAR_BITS; \
	B[7] = tmp; \
}
# endif
#endif


/*
 * put zero in `D[0..7]'.
 */

#if (UNSIGNED_LONG_BITS == 32) && ! defined(UNSIGNED_LONG_ALIGN)
# define	ZERO_8(D) \
	*((unsigned long *) D) = *((unsigned long *) &D[4]) = 0x0l
#else 
# if (UNSIGNED_LONG_BITS == 64) && ! defined(UNSIGNED_LONG_ALIGN)
#   define	ZERO_8(D) \
	*((unsigned long *) D) = 0x0l
# else
#   define	ZERO_8(D) \
	D[0] = D[1] = D[2] = D[3] = D[4] = D[5] = D[6] = D[7] = 0x00
# endif
#endif


/*
 * copy `S[0..7] to `D[0..7]'.
 */

#if (UNSIGNED_LONG_BITS == 32) && ! defined(UNSIGNED_LONG_ALIGN)
# define	COPY_8(D, S) \
	*((unsigned long *) D) = *((unsigned long *) S); \
	*((unsigned long *) &D[4]) = *((unsigned long *) &S[4])
#else 
# if (UNSIGNED_LONG_BITS == 64) && ! defined(UNSIGNED_LONG_ALIGN)
#  define	COPY_8(D, S) \
	*((unsigned long *) D) = *((unsigned long *) S)
# else
#  define	COPY_8(D, S) \
	D[0] = S[0]; D[1] = S[1]; D[2] = S[2]; D[3] = S[3]; \
	D[4] = S[4]; D[5] = S[5]; D[6] = S[6]; D[7] = S[7]
# endif
#endif


/*
 * xor `D[0..7]' with `V[0..7]' and store the result in `D[0..7]`.
 */

#if (UNSIGNED_LONG_BITS == 32) && ! defined(UNSIGNED_LONG_ALIGN)
# define	XOR_8(D, V) \
	*((unsigned long *) D) ^= *((unsigned long *) V); \
	*((unsigned long *) &D[4]) ^= *((unsigned long *) &V[4])
#else 
# if (UNSIGNED_LONG_BITS == 64) && ! defined(UNSIGNED_LONG_ALIGN)
#  define	XOR_8(D, V) \
	*((unsigned long *) D) ^= *((unsigned long *) V)
# else
#  define	XOR_8(D, V) \
	D[0] ^= V[0]; D[1] ^= V[1]; D[2] ^= V[2]; D[3] ^= V[3]; \
	D[4] ^= V[4]; D[5] ^= V[5]; D[6] ^= V[6]; D[7] ^= V[7]
# endif
#endif


/*
 * Compare `A[0..7]' with `B[0..7]'. 1 => equal, 0 => not equal .
 */

#if (UNSIGNED_LONG_BITS == 32) && ! defined(UNSIGNED_LONG_ALIGN)
# define	CMP_8(A, B) \
	(*((unsigned long *) A) == *((unsigned long *) B) && \
	 *((unsigned long *) &A[4]) == *((unsigned long *) &B[4]))
#else 
# if (UNSIGNED_LONG_BITS == 64) && ! defined(UNSIGNED_LONG_ALIGN)
#  define	CMP_8(A, B) \
	(*((unsigned long *) A) == *((unsigned long *) B))
# else
#  define	CMP_8(A, B) \
	(A[0] == B[0] && A[1] == B[1] && A[2] == B[2] && A[3] == B[3] && \
	 A[4] == B[4] && A[5] == B[5] && A[6] == B[6] && A[7] == B[7])
# endif
#endif


/*
 * xor `V1[0..7]' with `V2[0..7]' and store the result in `D[0..7]`.
 */

#if (UNSIGNED_LONG_BITS == 32) && ! defined(UNSIGNED_LONG_ALIGN)
# define	XOR2_8(D, V1, V2) \
	*((unsigned long *) D) = *((unsigned long *) V1) ^ \
				 *((unsigned long *) V2); \
	*((unsigned long *) &D[4]) = *((unsigned long *) &V1[4]) ^ \
				       *((unsigned long *) &V2[4])
#else 
# if (UNSIGNED_LONG_BITS == 64) && ! defined(UNSIGNED_LONG_ALIGN)
#  define	XOR2_8(D, V1, V2) \
	*((unsigned long *) D) = *((unsigned long *) V1) ^ \
				 *((unsigned long *) V2)
# else
#  define	XOR2_8(D, V1, V2) \
	D[0] = V1[0] ^ V2[0]; D[1] = V1[1] ^ V2[1]; \
	D[2] = V1[2] ^ V2[2]; D[3] = V1[3] ^ V2[3]; \
	D[4] = V1[4] ^ V2[4]; D[5] = V1[5] ^ V2[5]; \
	D[6] = V1[6] ^ V2[6]; D[7] = V1[7] ^ V2[7]
# endif
#endif


/*
 * shift `D[1..7]' to `D[0..6]' and put `N' in `D[7]'.
 */

#if (UNSIGNED_LONG_BITS == 32) && ! defined(UNSIGNED_LONG_ALIGN)
# ifdef UNSIGNED_LSB_FIRST
#  define	SHIFT_RIGHT_8(D, N) \
	*((unsigned long *) D) >>= 8; D[4] = D[5]; \
	*((unsigned long *) &D[4]) >>= 8; D[7] = N
# else
#  define	SHIFT_RIGHT_8(D, N) \
	*((unsigned long *) D) <<= 8; D[4] = D[5]; \
	*((unsigned long *) &D[4]) <<= 8; D[7] = N
# endif
#else
# if (UNSIGNED_LONG_BITS == 64) && ! defined(UNSIGNED_LONG_ALIGN)
#  ifdef UNSIGNED_LSB_FIRST
#   define	SHIFT_RIGHT_8(D, N) \
	*((unsigned long *) D) >>= 8; D[7] = N
#  else
#   define	SHIFT_RIGHT_8(D, N) \
	*((unsigned long *) D) <<= 8; D[7] = N
#  endif
# else
#  define	SHIFT_RIGHT_8(D, N) \
	D[0] = D[1]; D[1] = D[2]; D[2] = D[3]; D[3] = D[4]; \
	D[4] = D[5]; D[5] = D[6]; D[6] = D[7]; D[7] = N
# endif
#endif


/*
 * Rotate the bits in an unsigned character.
 */

#define CHAR_ROTATE(c)  \
	c = ((c & 0x0f) << 4) | ((c & 0xf0) >> 4); \
	c = ((c & 0x33) << 2) | ((c & 0xcc) >> 2); \
	c = ((c & 0x55) << 1) | ((c & 0xaa) >> 1)
