#include	<stdio.h>
#include	"compile.h"
#include	"fips_def.h"
#include	"fips_E.h"

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
 * This program generates a macro definition for us as the expansion E.
 *
 *	E(B, R)
 *
 * The input is 32 bits in the unsigned long `R' with the least significant
 * bit as the first. The output is the least significant six bits in each
 * unsigned character B[0] .. B[7], with the first bit as the least significant
 * bit of B[0].
 */

main()
{
	register int		n, s_min, s_max, r, c, bit, s, sh, sp, se;
	register unsigned long	b;
	unsigned long		st[E_ROWS][DES_R_BITS * 2];
	unsigned long		nb[E_ROWS][DES_R_BITS * 2];
	int			b_set[E_ROWS];


	s_min = DES_R_BITS * 2;
	s_max = 0;
	for (r = 0; r < E_ROWS; r++) {

		b_set[r] = 0;

		for (s = 0; s < DES_R_BITS * 2; s++)
			nb[r][s] = st[r][s] = 0x0l;

		for (bit = 1, c = 0; c < E_COLUMNS; bit++, c++) {
			sh = bit - e[r][c];
			s = DES_R_BITS + sh;
			st[r][s] |= 0x1 << (e[r][c] - 1);
			nb[r][s]++;
			if (s > s_max)
				s_max = s;
			if (s < s_min)
				s_min = s;
		}
	}

	printf("/*\n");
	printf(" * This file is automaticly generated, do not change.\n");
	printf(" */\n\n");
	printf("#define E_DATA register unsigned long\ter\n\n");
	printf("#define E(B, R) \\\n");
	printf("\ter = R; \\\n");
	for (n = sp = 0, s = DES_R_BITS; s <= s_max; s++)
		for (r = 0; r < E_ROWS; r++) {
			if (!st[r][s])
				continue;
			if (n++)
				printf("; \\\n");
			sh = s - DES_R_BITS;
			se = sh - sp;
			b = st[r][s] << sh;
			if (nb[r][s] > 1) {
				printf("\ter <<= %d; \\\n", se);
				if (b_set[r]++)
					printf("\tB[%d] |= er & 0x%08xl", r, b);
				else
					printf("\tB[%d] = er & 0x%08xl", r, b);
				sp = sh;
			} else {
				if (b_set[r]++) {
					printf("\tif (er & 0x%08xl) \\\n",
						st[r][s] << sp);
					printf("\t\tB[%d] |= 0x%08xl", r, b);
				} else {
					printf("\tB[%d] = (er & 0x%08xl) ? ",
						r, st[r][s] << sp);
					printf("0x%08xl : 0x%08xl", b, 0x0l);
				}
			}
		}
	if (sp) {
		sp = 0;
		printf("; \\\n\ter = R");
	}
	for (s = DES_R_BITS - 1; s >= s_min; s--)
		for (r = 0; r < E_ROWS; r++) {
			if (!st[r][s])
				continue;
			if (n++)
				printf("; \\\n");
			sh = s - DES_R_BITS;
			se = sh - sp;
			b = st[r][s] >> -sh;
			if (nb[r][s] > 1) {
				printf("\ter >>= %d; \\\n", -se);
				if (b_set[r]++)
					printf("\tB[%d] |= er & 0x%08xl", r, b);
				else
					printf("\tB[%d] = er & 0x%08xl", r, b);
				sp = sh;
			} else {
				if (b_set[r]++) {
					printf("\tif (er & 0x%08xl) \\\n",
						st[r][s] >> -sp);
					printf("\t\tB[%d] |= 0x%08xl", r, b);
				} else {
					printf("\tB[%d] = (er & 0x%08xl) ? ",
						r, st[r][s] >> -sp);
					printf("0x%08xl : 0x%08xl", b, 0x0l);
				}
			}
		}
	printf("\n");
/*
	for (r = 0; r < E_ROWS; r++) {
		printf("\tB[%d] = (", r);
		for (s = min_s[r]; s <= max_s[r]; s++)
			if (nb[r][s]) {
				printf("((er & 0x%08x) ", st[r][s]);
				sh = s - DES_R_BITS;
				if (sh > 0)
					printf("<< %2d)", sh);
				else if (sh < 0)
					printf(">> %2d)", -sh);
				else
					printf("     )");
				printf((--nb[r][s]) ? ")" : " | ");
			}
		printf((r + 1 < E_ROWS) ? "; \\\n" : "\n");
	}
*/

	exit(0);
}
