#include	<stdio.h>
#include	"des.h"
#include	"version.h"

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
 * des_print_cblock
 *
 *	prints the contentse of a `cblock' as 16 hexadecimal digits on
 *	stdout.
 *
 */


FILE	*des_print_file = stdout;
char	*des_print_format = "0x%02x%02x%02x%02x%02x%02x%02x%02x\n";


int	des_print_cblock(
#ifdef __STDC__
	des_cblock	*cblock,
	int		items)
#else
	cblock, items)
des_cblock	*cblock;
int		items;
#endif
{
	register int	n;


	for (n = 0; n < items && ! ferror(des_print_file); n++, cblock++)
		fprintf(des_print_file, des_print_format,
			(*cblock)[0], (*cblock)[1], (*cblock)[2], (*cblock)[3],
			(*cblock)[4], (*cblock)[5], (*cblock)[6], (*cblock)[7]);

	return n;
}
