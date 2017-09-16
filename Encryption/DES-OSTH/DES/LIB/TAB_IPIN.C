#include	<stdio.h>
#include	"des.h"
#include	"compile.h"
#include	"fips_def.h"
#include	"fips_IPinv.h"

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
 * This program generates a macro for us as inverse initial permutation.
 *
 *		IPinv(B, L, R)
 *
 * The input are two unsigned long's `L' and `R' with `L' as the first
 * 32 bits in the block and `R' as the rest. The first bit of each `L'
 * and `R' are the least significant of each.
 * The ouput is an array of unsigned characters `B[0..7]' with the
 * least significant bit of `B[0]' as the first bit.
 *
 * The macro IPinv_DATA must be placed in the declaration section in the
 * enclosing procedure to IPinv. It contains variables used by IPinv;
 */


main()
{
#if defined(USE_IF) || defined(USE_SHIFT)
# ifdef USE_SHIFT
	register int		shift;
# else  /* USE_SHIFT */
	register unsigned long	bb;
# endif /* USE_SHIFT */
	register int		n, r, c, block_bit, byte, bit, byte_bit;
	register unsigned long	b;


        printf("/*\n");
	printf(" * This file is automaticly generated, do not change.\n");
	printf(" */\n\n");
	printf("#define IPinv(B, L, R) \\\n\\\n");
	for (n = byte = byte_bit = block_bit = r = 0; r < IPinv_ROWS; r++)
		for (c = 0; c < IPinv_COLUMNS; c++) {
			if (++byte_bit == 1) {
# ifdef USE_SHIFT
				printf("\tB[%d] = ( \\\n", byte);
# else  /* USE_SHIFT */
				printf("\tB[%d] = 0x00; \\\n", byte);
# endif /* USE_SHIFT */
			}
		
			n = (ip_inv[r][c] - 1) / DES_L_BITS;
			bit = ip_inv[r][c] - (n * DES_L_BITS);
			b = 0x01 << (bit - 1);
# ifdef USE_SHIFT
#  ifdef DES_LSB_FIRST
			shift = byte_bit - bit;
#  else  /* DES_LSB_FIRST */
			shift = (UNSIGNED_CHAR_BITS + 1 - byte_bit) - bit;
#  endif /* DES_LSB_FIRST */
			printf("\t\t((%c & 0x%08x)", n ? 'R' : 'L', b);
			if (shift > 0) 
				printf(" << %2d", shift);
			else if (shift < 0)
				printf(" >> %2d", -shift);
			else
				printf("      ");
			if (byte_bit == UNSIGNED_CHAR_BITS) {
				printf(")   /* bit %2d */ \\\n", ++block_bit);
				printf((++byte < DES_BLOCK_BYTES) ?
					"\t); \\\n\\\n" : "\t)\n");
				byte_bit = 0;
			} else
				printf(") | /* bit %2d */ \\\n", ++block_bit);
# else  /* USE_SHIFT */
#  ifdef DES_LSB_FIRST
			bb = 0x01 << (byte_bit - 1);
#  else  /* DES_LSB_FIRST */
			bb = 0x01 << (UNSIGNED_CHAR_BITS - byte_bit);
#  endif /* DES_LSB_FIRST */
			printf("\tif (%c & 0x%08xl) B[%d] |= 0x%02x",
				n ? 'R' : 'L', b, byte, bb);
			if (byte_bit == UNSIGNED_CHAR_BITS) {
				if (++byte < DES_BLOCK_BYTES)
					printf("; /* %2d -> %2d */ \\\n\\\n",
						ip_inv[r][c], ++block_bit);
				else
					printf("  /* %2d -> %2d */\n",
						ip_inv[r][c], ++block_bit);
				byte_bit = 0;
			} else
				printf("; /* %2d -> %2d */ \\\n",
					ip_inv[r][c], ++block_bit);
# endif /* USE_SHIFT */
		}
#else  /* USE_IF || USE_SHIFT */
	register unsigned long	l, r;
	register int		i, j, byte, bit, n, sb, row, col;
	unsigned long		lv[UNSIGNED_CHAR_MAX + 1];
	unsigned long		rv[UNSIGNED_CHAR_MAX + 1];


        printf("/*\n");
	printf(" * This file is automaticly generated, do not change.\n");
	printf(" */\n\n");
	printf("CONST\tstruct {\n\t\tunsigned long\tl, r;\n\t} ip_inv[%d][%d]",
		DES_BLOCK_BYTES, UNSIGNED_CHAR_MAX + 1);
	printf(" = {\n\t\t{\n");
	*lv = 0x0l;
	*rv = 0x0l;
	for (byte = 0; byte < DES_BLOCK_BYTES; byte++) {
		for (bit = 0; bit < UNSIGNED_CHAR_BITS; bit++) {
			sb = (byte * UNSIGNED_CHAR_BITS + bit) + 1;
			/*
			 * row and col can't be used directly as index
			 * variables due to the C-compiler on PS/2.
			 */
			row = col = 0;
			for (i = 0; i < IPinv_ROWS; i++)
				for (j = 0; j < IPinv_COLUMNS; j++)
					if (sb == ip_inv[i][j]) {
						row = i;
						col = j;
						goto next;
					}
next:
			sb = row * IPinv_COLUMNS;
# ifdef DES_LSB_FIRST
			sb += col;
# else
			sb += (UNSIGNED_CHAR_BITS - 1) - col;
# endif
			if (sb >= DES_L_BITS) {
				l = 0x0l;
				r = 0x1l << (sb - DES_L_BITS);
			} else {
				l = 0x1l << sb;
				r = 0x0l;
			}
			n = 0x1 << bit;
			lv[n] = l;
			rv[n] = r;
			if (n > 1)
				for (i = 1, j = n + 1; i < n; i++, j++) {
					lv[j] = l | lv[i];
					rv[j] = r | rv[i];
				}
		}
		for (i = 0; i < UNSIGNED_CHAR_MAX; i++)
			printf("\t\t\t{ 0x%08xl, 0x%08xl },\n", lv[i], rv[i]);
		printf("\t\t\t{ 0x%08xl, 0x%08xl }\n\t\t}", lv[i], rv[i]);
		if (byte < DES_BLOCK_BYTES - 1)
			printf(", {\n");
	}
	printf("\n\t};\n\n");
	printf("#define IPinv_DATA des_cblock\t\tobp; \\\n");
	printf("\t\tregister unsigned long\tol, or\n\n");
	printf("#define IPinv(B, L, R) \\\n\\\n");
	printf("\tLONG_TO_CHAR_8(obp, L, R); \\\n");
	printf("\tol  = ip_inv[0][obp[0]].l; or  = ip_inv[0][obp[0]].r; \\\n");
	for (i = 1; i < DES_BLOCK_BYTES; i++)
		printf("\tol |= ip_inv[%d][obp[%d]].l; or |= ip_inv[%d][obp[%d]].r; \\\n",
			i, i, i, i);
	printf("\tLONG_TO_CHAR_8(B, ol, or)\n");
	
#endif /* USE_IF || USE_SHIFT */

	exit(0);
}
