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
	register char		*prog;
	register unsigned int	i, key;
	des_key_schedule	schedule;
	des_cblock		b;


	prog = rindex(*argv, '/');
	if (prog == NULL)
		prog = *argv;
	else
		prog++;

	if (argc == 2) {
		i = atoi(argv[1]);
		key = 0;
	} else if (argc == 3 && !strcmp(argv[1], "-k")) {
		i = atoi(argv[2]);
		key = 1;
	} else
		goto usage;

	if (key) 
		while (i-- > 0) 
			VOID des_key((des_cblock *) b, schedule);
	else
		while (i-- > 0) 
			VOID des_dea((des_cblock *) b, (des_cblock *) b,
				     schedule, DES_ENCRYPT);

	exit(0);
usage:
	fprintf(stderr, "Usage: %s [-k] iterations\n", prog);
	exit(1);
}
