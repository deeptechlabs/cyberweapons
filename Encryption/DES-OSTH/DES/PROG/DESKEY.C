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


main(argc, argv)
int	argc;
char	*argv[];
{
	register char	*prog;
	des_cblock	key;


	prog = rindex(*argv, '/');
	if (prog == NULL)
		prog = *argv;
	else
		prog++;


	if (argc == 1) {
		VOID des_read_password((des_cblock *) key, "Key: ", 1);
	} else if (argc == 2 && !strcmp(argv[1], "-r")) {
		VOID des_random_key((des_cblock *) key);
	} else if (argc == 3 && !strcmp(argv[1], "-k")) {
		VOID des_string_to_key(argv[2], key);
	} else {
		fprintf(stderr, "Usage %s [-r|-k key]\n", prog);
		exit(1);
	}

	VOID des_print_cblock((des_cblock *) key, 1);

	exit(0);
}
