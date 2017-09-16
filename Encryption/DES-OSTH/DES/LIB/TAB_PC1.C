#include	<stdio.h>
#include	"des.h"
#include	"compile.h"
#include	"fips_def.h"
#include	"fips_PC1.h"

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
 * This program generates a macro for us as permutated choise 1.
 *
 *		PC1(C0, D0, KEY)
 *
 * The input is an array of unsigned characters with the least significant
 * bit of `KEY[0]' as the first bit.
 * The 28 bit output is stored into the 28 least significant bits of
 * `C0' and `D0' with the least significant bit as the first.
 */


main()
{
#ifdef USE_SHIFT
	register int	n, r, c, block_bit, byte, n_bit, bit, s;


        printf("/*\n");
	printf(" * This file is automaticly generated, do not change.\n");
	printf(" */\n\n");
	printf("#define PC1(C0, D0, KEY) \\\n");
	for (n = block_bit = n_bit = r = 0; r < PC1_ROWS; r++)
		for (c = 0; c < PC1_COLUMNS; c++) {
			if (++n_bit == 1)
				printf("\t%c0 = ( \\\n", n++ ? 'D' : 'C');
			byte = (pc1[r][c] - 1) / DES_BLOCK_BYTES;
			bit = pc1[r][c] - (byte * DES_BLOCK_BYTES);
			printf("\t\t((KEY[%d] & 0x%02x)", byte,
# ifdef DES_LSB_FIRST
				0x01 << (bit - 1));
			s = n_bit - bit;
# else
				0x80 >> (bit - 1));
			s = n_bit - (UNSIGNED_CHAR_BITS + 1 - bit);
# endif
			if (s > 0) 
				printf(" << %2d", s);
			else if (s < 0)
				printf(" >> %2d", -s);
			else
				printf("      ");
			if (n_bit == DES_C_BITS) {
				printf(")   /* bit %2d */ \\\n", ++block_bit);
				printf((block_bit == DES_C_BITS) ?
					"\t); \\\n\\\n" : "\t)\n");
				n_bit = 0;
			} else
				printf(") | /* bit %2d */ \\\n", ++block_bit);
		}
#else  /* USE_SHIFT */
# ifdef USE_IF
	register int	n, r, c, block_bit, byte, bit;
	unsigned char	c0[DES_BLOCK_BYTES][UNSIGNED_CHAR_BITS];
	unsigned char	d0[DES_BLOCK_BYTES][UNSIGNED_CHAR_BITS];


	for (r = 0; r < DES_BLOCK_BYTES; r++)
		for (c = 0; c < UNSIGNED_CHAR_BITS; c++)
			c0[r][c] = d0[r][c] = 0;
	for (block_bit = r = 0; r < PC1_ROWS; r++)
		for (c = 0; c < PC1_COLUMNS; block_bit++, c++) {
			byte = (pc1[r][c] - 1) / DES_BLOCK_BYTES;
			bit = pc1[r][c] - (byte * DES_BLOCK_BYTES);
#  ifdef DES_LSB_FIRST
			bit--;
#  else
			bit = UNSIGNED_CHAR_BITS - bit;
#  endif
			if (block_bit < DES_C_BITS)
				c0[byte][bit] = (unsigned char) block_bit + 1;
			else
				d0[byte][bit] = (unsigned char) block_bit -
						(DES_C_BITS - 1);
		}
        printf("/*\n");
	printf(" * This file is automaticly generated, do not change.\n");
	printf(" */\n\n");
	printf("#define PC1(C0, D0, KEY) \\\n");
	printf("\tC0 = 0x0l; \\\n");
	for (byte = 0; byte < DES_BLOCK_BYTES; byte++) {
		for (bit = 0; bit < UNSIGNED_CHAR_BITS; bit++) {
			if (!c0[byte][bit])
				continue;
			printf("\tif (KEY[%d] & 0x%02x) C0 |= 0x%08xl", byte, 
				0x1 << bit, 0x1l << c0[byte][bit] - 1);
			printf("; /* %2d */ \\\n", c0[byte][bit]);
		}
	}
	printf("\tD0 = 0x0l; \\\n");
	for (n = 0, byte = DES_BLOCK_BYTES - 1; byte >= 0; byte--) {
		for (bit = 0; bit < UNSIGNED_CHAR_BITS; bit++) {
			if (!d0[byte][bit])
				continue;
			printf("\tif (KEY[%d] & 0x%02x) D0 |= 0x%08xl", byte, 
				0x1 << bit, 0x1l << d0[byte][bit] - 1);
			if (++n == DES_C_BITS)
				printf("  /* %2d */\n", d0[byte][bit]);
			else
				printf("; /* %2d */ \\\n", d0[byte][bit]);
		}
	}
# else  /* USE_IF */
	register unsigned long	c, d;
	register int		i, j, byte, bit, n, sb, row, col;
	unsigned long		cv[UNSIGNED_CHAR_MAX + 1];
	unsigned long		dv[UNSIGNED_CHAR_MAX + 1];


        printf("/*\n");
	printf(" * This file is automaticly generated, do not change.\n");
	printf(" */\n\n");
	printf("CONST\tstruct {\n\t\tunsigned long\tc, d;\n\t} pc1[%d][%d]",
		DES_BLOCK_BYTES, UNSIGNED_CHAR_MAX + 1);
	printf(" = {\n\t\t{\n");
	*cv = 0x0l;
	*dv = 0x0l;
#  ifdef DES_LSB_FIRST
	cv[(UNSIGNED_CHAR_MAX + 1) / 2] = 0x0l;
	dv[(UNSIGNED_CHAR_MAX + 1) / 2] = 0x0l;
#  else DES_LSB_FIRST
	cv[1] = 0x0l;
	dv[1] = 0x0l;
#  endif
	for (byte = 0; byte < DES_BLOCK_BYTES; byte++) {
#  ifdef DES_LSB_FIRST
		for (bit = 0; bit < UNSIGNED_CHAR_MAX + 1; bit++) {
			sb = (byte * UNSIGNED_CHAR_BITS + bit) + 1;
#  else
		for (bit = 1; bit < UNSIGNED_CHAR_BITS; bit++) {
			sb = (byte * UNSIGNED_CHAR_BITS +
				((UNSIGNED_CHAR_BITS - 1) - bit)) + 1;
#  endif
                        /*
			 * row and col can't be used directly as index
			 * variables due to the C-compiler on PS/2.
			 */
			row = col = 0;
			for (i = 0; i < PC1_ROWS; i++)
				for (j = 0; j < PC1_COLUMNS; j++)
					if (sb == pc1[i][j]) {
						row = i;
						col = j;
						goto next;
					}
next:
			sb = (row * PC1_COLUMNS) + col;
			if (sb >= DES_C_BITS) {
				c = 0x0l;
				d = 0x1l << (sb - DES_C_BITS);
			} else {
				c = 0x1l << sb;
				d = 0x0l;
			}
			n = 0x1 << bit;
			cv[n] = c;
			dv[n] = d;
#  ifdef DES_LSB_FIRST
			cv[n + ((UNSIGNED_CHAR_MAX + 1) / 2)] = c;
			dv[n + ((UNSIGNED_CHAR_MAX + 1) / 2)] = d;
			if (n > 1)
				for (i = 1, j = n + 1; i < n; i++, j++) {
					cv[j + ((UNSIGNED_CHAR_MAX + 1) / 2)] =
						cv[j] = c | cv[i];
					cv[j + ((UNSIGNED_CHAR_MAX + 1) / 2)] =
						dv[j] = d | dv[i];
				}
#  else
			cv[n + 1] = c;
			dv[n + 1] = d;
			if (n > 2)
				for (i = 2, j = n + 2; i < n; i++, j++) {
					cv[j] = c | cv[i];
					dv[j] = d | dv[i];
				}
#  endif
		}
		for (i = 0; i < UNSIGNED_CHAR_MAX; i++)
			printf("\t\t\t{ 0x%08xl, 0x%08xl },\n", cv[i], dv[i]);
		printf("\t\t\t{ 0x%08xl, 0x%08xl }\n\t\t}", cv[i], dv[i]);
		if (byte < DES_BLOCK_BYTES - 1)
			printf(", {\n");
	}
	printf("\n\t};\n\n");
	printf("#define PC1(C, D, KEY) \\\n\\\n");
	printf("\tC  = pc1[0][KEY[0]].c; D  = pc1[0][KEY[0]].d; \\\n");
	for (i = 1; i < DES_BLOCK_BYTES - 1; i++)
		printf("\tC |= pc1[%d][KEY[%d]].c; D |= pc1[%d][KEY[%d]].d; \\\n",
			i, i, i, i);
	printf("\tC |= pc1[%d][KEY[%d]].c; D |= pc1[%d][KEY[%d]].d\n",
		i, i, i, i);
	
# endif /* USE_IF */
#endif /* USE_SHIFT */
	exit(0);
}
