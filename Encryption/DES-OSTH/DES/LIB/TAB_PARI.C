#include	<stdio.h>
#include	"des.h"
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
 * This program generates a table to use for key parity adjustment.
 *
 */

main()
{
	register int		i, bit;
	register unsigned char	res, p;
#ifdef DES_LSB_FIRST
	unsigned char		resv[(UNSIGNED_CHAR_MAX + 1) / 2];
#endif


        printf("/*\n");
	printf(" * This file is automaticly generated, do not change.\n");
	printf(" */\n\n");
	printf("CONST unsigned char\tparity_tab[%d] = {\n",
		UNSIGNED_CHAR_MAX + 1);
#ifdef DES_LSB_FIRST
	for (i = 0; i < (UNSIGNED_CHAR_MAX + 1) / 2; i++) {

		res = (unsigned char) i;
		
		for (p = 0x80, bit = 0x01; bit <= 0x80; bit <<= 1)
			if (res & bit)
				p ^= 0x80;

		resv[i] = (res |= p);

		printf("\t\t\t\t0x%02x,\n", res);
	}
	for (i = 0; i < ((UNSIGNED_CHAR_MAX + 1) / 2) - 1; i++)
		printf("\t\t\t\t0x%02x,\n", resv[i]);
	printf("\t\t\t\t0x%02x\n", resv[i]);
#else
	for (i = 0; i < UNSIGNED_CHAR_MAX + 1; i += 2) {

		res = (unsigned char) i;
		
		for (p = 0x01, bit = 0x80; bit >= 0x02; bit >>= 1)
			if (res & bit)
				p ^= 0x01;

		res |= p;

		printf("\t\t\t\t0x%02x,\n", res);
		if (i < UNSIGNED_CHAR_MAX)
			printf("\t\t\t\t0x%02x,\n", res);
		else
			printf("\t\t\t\t0x%02x\n", res);
	}
#endif
	printf("\t\t\t};\n");

	exit(0);
}
