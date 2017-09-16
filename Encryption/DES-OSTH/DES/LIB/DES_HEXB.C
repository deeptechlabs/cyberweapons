#include	<stdio.h>
#include	"des.h"
#include	"local_def.h"
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
 * des_hex_to_cblock
 *
 *	Generation of a cblock from a string contaning 16 hexadecimal
 *	digits. The string may have an optional "0x" or "0X" prepended.
 *
 *	The function returns -1 if the string does not contain excatly
 *	16 digits or if any non hexadecimal characters are found.
 *
 *	`cblock' is modified if the function returns -1.
 *
 */


char	*des_scan_format = "%2x%2x%2x%2x%2x%2x%2x%2x";


int	des_hex_to_cblock(
#ifdef __STDC__
	char		*str,
	des_cblock	*cblock)
#else
	str, cblock)
char		*str;
des_cblock	*cblock;
#endif
{
	int			buf[DES_BLOCK_BYTES];
	register char		*sp;


	sp = str;

	if (!sp)
		return -1;

	/*
	 * Remove "0x" or "0X".
	 */
	if (*sp == '0' && (sp[1] == 'x' || sp[1] == 'X'))
		sp += 2;

	if (sscanf(sp, des_scan_format,
		   &buf[0], &buf[1], &buf[2], &buf[3],
		   &buf[4], &buf[5], &buf[6], &buf[7]) != DES_BLOCK_BYTES)
		return -1;

	(*cblock)[0] = (unsigned char) buf[0];
	(*cblock)[1] = (unsigned char) buf[1];
	(*cblock)[2] = (unsigned char) buf[2];
	(*cblock)[3] = (unsigned char) buf[3];
	(*cblock)[4] = (unsigned char) buf[4];
	(*cblock)[5] = (unsigned char) buf[5];
	(*cblock)[6] = (unsigned char) buf[6];
	(*cblock)[7] = (unsigned char) buf[7];

	return 0;
}
