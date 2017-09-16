#include	"compile.h"
#include	<stdio.h>
#include	<strings.h>
#include	<des.h>

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

#ifdef __STDC__
# define VOID (void)
#else
# define VOID
#endif


main(argc, argv)
int	argc;
char	*argv[];
{
	register char		*prog;
	register unsigned int	byte, bit, i;
	des_key_schedule	schedule;
	des_cblock		key, b;


	prog = rindex(*argv, '/');
	if (prog == NULL)
		prog = *argv;
	else
		prog++;

	if (argc == 2) {
		printf("STRKEY = \"%s\"\n\n", argv[1]);
		VOID des_string_to_key(argv[1], key);
	} else if (argc == 3 && !strcmp(argv[1], "-h")) {
		if (des_hex_to_cblock(argv[2], (des_cblock *) key) < 0)
			goto badhex;
		printf("HEXKEY = \"%s\"\n\n", argv[2]);
	} else
		goto usage;

	printf("   KEY = ");
	des_print_cblock((des_cblock *) key, 1);
	printf("PARITY = %s\n\n", des_test_key_parity((des_cblock *) key) ?
		"CORRECT (ODD)" : "INCORRECT");

	VOID des_key((des_cblock *) key, schedule);


	printf("  KEYS = %d\n", des_no_key_schedule((des_cblock *) key));
	for (i = 0; i < 16; i++) {
		printf("KS[%2d] = ", i);
		des_print_cblock((des_cblock *) schedule[i]._, 1);
	}

	printf("\n");

	for (byte = 0; byte < DES_BLOCK_BYTES; byte++) {
		for (bit = 0x80; bit >= 0x01; bit >>= 1) {
			bzero((char *) b, DES_BLOCK_BYTES);
			b[byte] = bit;
			printf("   IN = ");
			des_print_cblock((des_cblock *) b, 1);
			VOID des_dea((des_cblock *) b, (des_cblock *) b,
				     schedule, DES_ENCRYPT);
			printf("CRYPT = ");
			des_print_cblock((des_cblock *) b, 1);
			VOID des_dea((des_cblock *) b, (des_cblock *) b,
				     schedule, DES_DECRYPT);
			printf("  OUT = ");
			des_print_cblock((des_cblock *) b, 1);
		}
	}
	exit(0);
usage:
	fprintf(stderr, "Usage: %s [-h] key\n", prog);
	exit(1);
badhex:
	fprintf(stderr, "%s: The key must be 16 hexadecimal numbers\n", prog);
	exit(1);
}
