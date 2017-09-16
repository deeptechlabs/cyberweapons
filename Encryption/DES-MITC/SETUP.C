/*
 *	Process Arguments to Command and Set Up Key and Permutation
 *	D.P.Mitchell  83/07/01.
 */

#include <stdio.h>
#include "crypt.h"

Block random;
int pflag;

Block
setup(argc, argv)
int argc;
char *argv[];
{
	char tempkey[128];
	Block key;
	char *keystring;
	int i;
	extern Block key_crunch(), recrunch(), rand_block();
	extern char *getpass(), *strcpy();

	if (--argc > 0 && argv[1][0] == '-' && argv[1][1] == 'p')
		pflag = 1;
	else
		argc++;
	if (argc > 2) {
		fprintf(stderr, "Usage: en/decrypt [-p] [key]\n");
		exit(1);
	}
	if (argc == 2)
		keystring = argv[1 + pflag];
	else {
		keystring = getpass("Enter Key: ");
		(void) strcpy(tempkey, keystring);
		keystring = getpass("Enter Key Again: ");
		if (strcmp(keystring, tempkey)) {
			fprintf(stderr, "Key Mistyped\n");
			exit(1);
		}
	}
	random = rand_block();
	key = key_crunch(keystring);
	while (*keystring)
		*keystring++ = '\0';
	/*
	 *	Repeating shuffle and recrunch prevents the recovery of
	 *	the key if the permutation becomes known.
	 */
	for (i = 0; i < 7; i++) {
		shuffle_permutation();
		key = recrunch();
	}
	return key;
}
