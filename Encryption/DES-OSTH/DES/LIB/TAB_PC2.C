#include	<stdio.h>
#include	"des.h"
#include	"compile.h"
#include	"fips_def.h"
#include	"fips_PC2.h"

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
 * This program generates a macro for us as permutated choise 2.
 *
 *		PC2(KSn, Cn, Dn)
 *
 * The input is 56 bits where the first 28 bits are stored in the 28 least
 * significant bits of `Cn' with the least signinficant bit as the first,
 * and the remaning 28 bits stored in the 28 least significant bits of `Dn'
 * with the least significant bit as the first.
 *
 * The output is 48 bits stored in an array of unsigned characters `KSn[0..7]'
 * with six bits in the six least significant bits of ecah character.
 * The least significant bit of each caracter is the first bit of each with
 * the least significant bit of `KSn[0]' as the first in the output block.
 */


#define DES_KS_BITS_PER_BYTE \
	(UNSIGNED_CHAR_BITS - ((DES_BITS - DES_KS_BITS) / DES_BLOCK_BYTES))


main()
{
#if defined(USE_SHIFT) || defined(USE_IF)
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
# ifndef USE_SHIFT
	printf("#define PC2_DATA register unsigned char\t*ksp\n\n");
# endif /* USE_SHIFT */
	printf("#define PC2(KSn, Cn, Dn) \\\n");
# ifndef USE_SHIFT
	printf("\tksp = (KSn); \\\n");
# endif /* ! USE_SHIFT */
	for (n = byte = byte_bit = r = 0, block_bit = 1; r < PC2_ROWS; r++)
		for (c = 0; c < PC2_COLUMNS; c++, block_bit++) {
			if (++byte_bit == 1) {
# ifdef USE_SHIFT
				printf("\tKSn[%d] = ( \\\n", byte);
# else  /* USE_SHIFT */
				if (byte > 0)
					printf("\t*++ksp = 0x00; \\\n", byte);
				else
					printf("\t*ksp = 0x00; \\\n", byte);
# endif /* USE_SHIFT */
			}
			n = (pc2[r][c] - 1) / DES_C_BITS;
			bit = pc2[r][c] - (n * DES_C_BITS);
			b = 0x1l << (bit - 1);
# ifdef USE_SHIFT
			printf("\t\t((%cn & 0x%08x)", n ? 'D' : 'C', b);
			shift = byte_bit - bit;
			if (shift > 0) 
				printf(" << %2d", shift);
			else if (shift < 0)
				printf(" >> %2d", -shift);
			else
				printf("      ");
			if (byte_bit == DES_KS_BITS_PER_BYTE) {
				printf(")   /* bit %2d */ \\\n", block_bit);
				printf((++byte < DES_BLOCK_BYTES) ?
					"\t); \\\n\\\n" : "\t)\n");
				byte_bit = 0;
			} else
				printf(") | /* bit %2d */ \\\n", block_bit);
# else  /* USE_SHIFT */
			bb = 0x1l << byte_bit - 1;
			printf("\tif (%s & 0x%08xl) *ksp |= 0x%02x",
				n ? "Dn" : "Cn", b, bb);
			if (byte_bit == DES_KS_BITS_PER_BYTE) {
				if (++byte < DES_BLOCK_BYTES)
					printf("; /* %2d -> %2d */ \\\n\\\n",
						pc2[r][c], block_bit);
				else
					printf("  /* %2d -> %2d */\n",
						pc2[r][c], block_bit);
				byte_bit = 0;
			} else
				printf("; /* %2d -> %2d */ \\\n",
					pc2[r][c], block_bit);
# endif /* USE_SHIFT */
		}
#else  /* USE_SHIFT || USE_IF */
	register unsigned long	c, d;
	register int		i, j, byte, bit, max, n, sb, row, col;
	unsigned long		cv[UNSIGNED_CHAR_MAX + 1];
	unsigned long		dv[UNSIGNED_CHAR_MAX + 1];


        printf("/*\n");
	printf(" * This file is automaticly generated, do not change.\n");
	printf(" */\n\n");
	printf("CONST\tstruct {\n\t\tunsigned long\tc, d;\n\t} pc2[%d][%d]",
		UNSIGNED_CHAR_BITS, UNSIGNED_CHAR_MAX + 1);
	printf(" = {\n\t\t{\n");
	*cv = 0x0l;
	*dv = 0x0l;
	for (byte = 0; byte < DES_BLOCK_BYTES; byte++) {
		if (byte == (DES_C_BITS / UNSIGNED_CHAR_BITS) ||
		    byte == (DES_C_BITS / UNSIGNED_CHAR_BITS) +
		    (DES_BLOCK_BYTES / 2))
			max = DES_C_BITS - (DES_KS_BITS / 2);
		else
			max = UNSIGNED_CHAR_BITS;
		for (bit = 0; bit < max; bit++) {
			if (byte < DES_BLOCK_BYTES / 2) 
				sb = (byte * UNSIGNED_CHAR_BITS + bit) + 1;
			else
				sb = ((byte - (DES_BLOCK_BYTES / 2)) *
				     UNSIGNED_CHAR_BITS + bit) + DES_C_BITS + 1;
			/*
			 * row and col can't be used directly as index
			 * variables due to the C-compiler on PS/2.
			 */
			row = PC2_ROWS;
			col = PC2_COLUMNS;
			for (i = 0; i < PC2_ROWS; i++)
				for (j = 0; j < PC2_COLUMNS; j++)
					if (sb == pc2[i][j]) {
						row = i;
						col = j;
						goto next;
					}
next:
			c = d = 0x0l;
			if (row < PC2_ROWS) {
				sb = (row * PC2_COLUMNS) + col;
				if (sb < (DES_KS_BITS / 2)) {
					sb += (sb / DES_KS_BITS_PER_BYTE) * 2;
					c = 0x1l << sb;
				} else {
					sb -= (DES_KS_BITS / 2);
					sb += (sb / DES_KS_BITS_PER_BYTE) * 2;
					d = 0x1l << sb;
				}
			}
			n = 0x1 << bit;
			cv[n] = c;
			dv[n] = d;
			if (n > 1)
				for (i = 1, j = n + 1; i < n; i++, j++) {
					cv[j] = c | cv[i];
					dv[j] = d | dv[i];
				}
		}
		if (byte == (DES_C_BITS / UNSIGNED_CHAR_BITS) ||
		    byte == (DES_C_BITS / UNSIGNED_CHAR_BITS) +
		    (DES_BLOCK_BYTES / 2))
			max = (0x1 << (DES_C_BITS -
			      ((DES_C_BITS / UNSIGNED_CHAR_BITS) *
			      UNSIGNED_CHAR_BITS))) - 1;
		else
			max = UNSIGNED_CHAR_MAX;
		for (i = 0; i < max; i++)
			printf("\t\t\t{ 0x%08xl, 0x%08xl },\n", cv[i], dv[i]);
		printf("\t\t\t{ 0x%08xl, 0x%08xl }\n\t\t}", cv[i], dv[i]);
		if (byte < (DES_BLOCK_BYTES - 1))
			printf(", {\n");
	}
	printf("\n\t};\n\n");
	printf("#define PC2_DATA des_cblock\tksp; \\\n");
	printf("\t\tregister unsigned long\toc, od\n\n");
	printf("#define PC2(KSn, Cn, Dn) \\\n\\\n");
	printf("\tLONG_TO_CHAR_8(ksp, Cn, Dn); \\\n");
	printf("\toc  = pc2[0][ksp[0]].c; od  = pc2[0][ksp[0]].d; \\\n");
	for (i = 1; i < DES_BLOCK_BYTES; i++)
		printf("\toc |= pc2[%d][ksp[%d]].c; od |= pc2[%d][ksp[%d]].d; \\\n",
			i, i, i, i);
	printf("\tLONG_TO_CHAR_8(KSn, oc, od)\n");
#endif /* USE_SHIFT || USE_IF */

	exit(0);
}
