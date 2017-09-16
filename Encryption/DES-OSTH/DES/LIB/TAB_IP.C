#include	<stdio.h>
#include	"des.h"
#include	"compile.h"
#include	"fips_def.h"
#include	"fips_IP.h"

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
 * This program generates a macro for us as initial permutation.
 *
 *		IP(L, R, B)
 *
 * The input is an array of unsigned characters `B[0..7]' with the first
 * bit as the * least significant bit of `B[0]'.
 * The output is two unsigned long's `L' with `R' with the first 32 bits in
 * `L' and the rest in `R'. The least significant bits in `L' and `R' are
 * the first bits in each.
 */


main()
{
#ifdef USE_SHIFT
	register int		r, c, block_bit, byte, bit, n_bit, shift;
	register unsigned long	b;
	register char		ch;


        printf("/*\n");
	printf(" * This file is automaticly generated, do not change.\n");
	printf(" */\n\n");
	printf("#define IP(L, R, B) \\\n");
	for (block_bit = n_bit = r = 0; r < IP_ROWS; r++)
		for (c = 0; c < IP_COLUMNS; c++) {
			if (++n_bit == 1) {
				ch = (block_bit > 0) ? 'R' : 'L';
				printf("\t%c = ( \\\n", ch);
			}
			byte = (ip[r][c] - 1) / UNSIGNED_CHAR_BITS;
			bit = ip[r][c] - byte * UNSIGNED_CHAR_BITS;
# ifdef DES_LSB_FIRST
			b = 0x01 << (bit - 1);
			shift = n_bit - bit;
# else
			b = 0x01 << (UNSIGNED_CHAR_BITS - bit);
			shift = n_bit - (UNSIGNED_CHAR_BITS + 1 - bit);
# endif
			printf("\t\t((B[%d] & 0x%02x)", byte, b);
			if (shift > 0) 
				printf(" << %2d", shift);
			else if (shift < 0)
				printf(" >> %2d", -shift);
			else
				printf("      ");
			if (n_bit == DES_L_BITS) {
				printf(")   /* bit %2d */ \\\n", ++block_bit);
				printf((block_bit == DES_L_BITS) ?
					"\t); \\\n\\\n" : "\t)\n");
				n_bit = 0;
			} else
				printf(") | /* bit %2d */ \\\n", ++block_bit);
		}
#else  /* USE_SHIFT */
# ifdef USE_IF
	register int	i, j, block_bit, byte, bit, n;
	unsigned char	r[DES_BLOCK_BYTES][UNSIGNED_CHAR_BITS];
	unsigned char	l[DES_BLOCK_BYTES][UNSIGNED_CHAR_BITS];


	for (i = 0; i < DES_BLOCK_BYTES; i++)
		for (j = 0; j < UNSIGNED_CHAR_BITS; j++)
			r[i][j] = l[i][j] = 0;
	for (block_bit = i = 0; i < IP_ROWS; i++)
		for (j = 0; j < IP_COLUMNS; block_bit++, j++) {
			byte = (ip[i][j] - 1) / UNSIGNED_CHAR_BITS;
			bit = ip[i][j] - (byte * UNSIGNED_CHAR_BITS);
#  ifdef DES_LSB_FIRST
			bit--;
#  else
			bit = UNSIGNED_CHAR_BITS - bit;
#  endif
			if (block_bit < DES_L_BITS)
				l[byte][bit] = (unsigned char) block_bit + 1;
			else
				r[byte][bit] = (unsigned char) (block_bit - 31);
		}
        printf("/*\n");
	printf(" * This file is automaticly generated, do not change.\n");
	printf(" */\n\n");
	printf("#define IP(L, R, B) \\\n\\\n");
	printf("\tL = 0x0l; \\\n");
	for (byte = 0; byte < DES_BLOCK_BYTES; byte++)
		for (bit = 0; bit < UNSIGNED_CHAR_BITS; bit++) {
			if (!l[byte][bit])
				continue;
			printf("\tif (B[%d] & 0x%02x) L |= 0x%08xl", byte,
				0x01 << bit, 0x1l << l[byte][bit] - 1);
			printf("; /* %2d */ \\\n", l[byte][bit]);
		}
	printf("\\\n\tR = 0x0l; \\\n");
	for (n = 0, byte = DES_BLOCK_BYTES - 1; byte >= 0; byte--)
		for (bit = 0; bit < UNSIGNED_CHAR_BITS; bit++) {
			if (!r[byte][bit])
				continue;
			printf("\tif (B[%d] & 0x%02x) R |= 0x%08xl", byte,
				0x01 << bit, 0x1l << r[byte][bit] - 1);
			if (++n == DES_R_BITS)
				printf("  /* %2d */\n", r[byte][bit] +
					DES_R_BITS);
			else
				printf("; /* %2d */ \\\n", r[byte][bit] +
					DES_R_BITS);
		}
# else /* USE_IF */
	register unsigned long	l, r;
	register int		i, j, byte, bit, n, sb, row, col;
	unsigned long		lv[UNSIGNED_CHAR_MAX + 1];
	unsigned long		rv[UNSIGNED_CHAR_MAX + 1];


        printf("/*\n");
	printf(" * This file is automaticly generated, do not change.\n");
	printf(" */\n\n");
	printf("CONST\tstruct {\n\t\tunsigned long\tl, r;\n\t} ip[%d][%d]",
		DES_BLOCK_BYTES, UNSIGNED_CHAR_MAX + 1);
	printf(" = {\n\t\t{\n");
	*lv = 0x0l;
	*rv = 0x0l;
	for (byte = 0; byte < DES_BLOCK_BYTES; byte++) {
		for (bit = 0; bit < UNSIGNED_CHAR_BITS; bit++) {
#  ifdef DES_LSB_FIRST
			sb = (byte * UNSIGNED_CHAR_BITS) + bit + 1;
#  else
			sb = ((byte * UNSIGNED_CHAR_BITS) +
			      ((UNSIGNED_CHAR_BITS - 1) - bit)) + 1;
#  endif
			/*
			 * row and col can't be used directly as index
			 * variables due to the C-compiler on PS/2.
			 */
			row = col = 0;
			for (i = 0; i < IP_ROWS; i++)
				for (j = 0; j < IP_COLUMNS; j++)
					if (sb == ip[i][j]) {
						row = i;
						col = j;
						goto next;
					}
next:
			sb = (row * IP_COLUMNS) + col;
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
	printf("#define IP(L, R, B) \\\n\\\n");
	printf("\tL  = ip[0][B[0]].l; R  = ip[0][B[0]].r; \\\n");
	for (i = 1; i < DES_BLOCK_BYTES - 1; i++)
		printf("\tL |= ip[%d][B[%d]].l; R |= ip[%d][B[%d]].r; \\\n",
			i, i, i, i);
	printf("\tL |= ip[%d][B[%d]].l; R |= ip[%d][B[%d]].r\n", i, i, i, i);
	
# endif /* USE_IF */
#endif /* USE_SHIFT */

	exit(0);
}
