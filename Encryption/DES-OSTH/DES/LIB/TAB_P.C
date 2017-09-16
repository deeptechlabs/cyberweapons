#include	<stdio.h>
#include	"compile.h"
#include	"fips_def.h"
#include	"fips_P.h"

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
 * This program generates a macro for us as the permutation.
 *
 *		P(R)
 *
 * The input is an unsigned long `R' with the least significant bit
 * as the first.
 * The output is an unsigned long with the least significant bit as the
 * first.
 */

main()
{
	register int	r, c, block_bit, shift, max_s, min_s;
	unsigned long	st[DES_BITS];


	for (shift = 0; shift < DES_BITS; shift++)
		st[shift] = 0x00;

	min_s = DES_L_BITS;
	max_s = -DES_L_BITS;
	for (block_bit = r = 0; r < P_ROWS; r++)
		for (c = 0; c < P_COLUMNS; c++) {
			shift = ++block_bit - p[r][c];
			st[DES_L_BITS + shift] |= 0x1 << (p[r][c] - 1);
			if (max_s < shift)
				max_s = shift;
			if (min_s > shift)
				min_s = shift;
		}

        printf("/*\n");
	printf(" * This file is automaticly generated, do not change.\n");
	printf(" */\n\n");
	printf("#define P(R) \\\n( \\\n");
	for (shift = min_s; shift <= max_s; shift++)
		if (st[DES_L_BITS + shift]) {
			printf("\t((R & 0x%08x) ", st[DES_L_BITS + shift]);
			if (shift > 0)
				printf("<< %2d)", shift);
			else if (shift < 0)
				printf(">> %2d)", -shift);
			else
				printf("     )");
			if (shift == max_s)
				printf(" \\\n");
			else
				printf(" | \\\n");
		}
	printf(")\n");

	exit(0);
}
