#include	<stdio.h>
#include	"compile.h"
#include	"fips_S.h"

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
 * Bit rotate for the four least significant bits.
 */

CONST unsigned char	r[16] = {
					0x0, /* 0000 -> 0000 */
					0x8, /* 0001 -> 1000 */
					0x4, /* 0010 -> 0100 */
					0xc, /* 0011 -> 1100 */
					0x2, /* 0100 -> 0010 */
					0xa, /* 0101 -> 1010 */
					0x6, /* 0110 -> 0110 */
					0xe, /* 0111 -> 1110 */
					0x1, /* 1000 -> 0001 */
					0x9, /* 1001 -> 1001 */
					0x5, /* 1010 -> 0101 */
					0xd, /* 1011 -> 1101 */
					0x3, /* 1100 -> 0011 */
					0xb, /* 1101 -> 1011 */
					0x7, /* 1110 -> 0111 */
					0xf  /* 1111 -> 1111 */
				};

/*
 * This program generates a macro for us as the S - selection.
 *
 *		S(B)
 *
 * The input is 48 bits stored in an array of unsigned character `B[0--7]'
 * with six bit in the six least significant bits of each character.
 * The least significant bit of each character is the first of each with
 * the least significant bit of `B[0]' as the first in the input block.
 *
 * The output is 32 bits in an unsigned long with the least significant bit
 * as the first.
 */

#define DES_KS_BITS_PER_BYTE \
	(UNSIGNED_CHAR_BITS - ((DES_BITS - DES_KS_BITS) / DES_BLOCK_BYTES))

#define DES_KS_BYTE_MAX = ((0x1 << DES_KS_BITS_PER_BYTE) - 1)

main()
{
	register int	i, j, sb, n, v;


        printf("/*\n");
	printf(" * This file is automaticly generated, do not change.\n");
	printf(" */\n\n");
	printf("CONST unsigned long	s[%d][%d] = {\n", S_BOXES,
		DES_KS_BYTE_MAX + 1);
	for (sb = 0; sb < S_BOXES; sb++) {
		printf("\t\t\t{ /* S%d                (i,  j) -> out */\n",
			sb + 1);
		for (n = 0; n < DES_KS_BYTE_MAX + 1; n++) {
			i = ((n & 0x01) << 1) | ((n & 0x20) >> 5);
			j = r[(n & 0x1e) >> 1];
			v = s[sb][i][j];
			printf("\t\t\t\t0x%08x%c /* (%d, %2d) -> %2d */\n",
				((unsigned long) r[v]) <<
				(sb * (UNSIGNED_CHAR_BITS / 2)),
				(n + 1 < DES_BITS) ? ',' : ' ', i, j, v);
		}
		printf(((sb + 1) < S_BOXES) ? "\t\t\t},\n" : "\t\t\t}\n");
	}
	printf("\t\t};\n\n#define S(B) ( \\\n");
	for (sb = 0; sb < S_BOXES; sb++) {
		printf("\ts[%d][B[%d]]", sb, sb);
		printf((sb + 1 < S_BOXES) ? " | \\\n" : " \\\n");
	}
	printf(")\n");
	exit(0);
}
