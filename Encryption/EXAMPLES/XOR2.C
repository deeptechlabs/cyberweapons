/* Alternative version of simple xor; uses stdin and stdout
   for file i/o (just like rot13 does) to simplify the exposition.
		--Ken Pizzini
		ken@halcyon.com
*/
/*
  SIMPLE XOR
*/

/* Usage:  crypto-xor key <input_file >output_file  */

#include <stdio.h>

int
main(int argc, char *argv[])
{
	char *cp;
	int c;

	if (argc!=2 || !(cp=argv[1]) || *cp=='\0'){
		fprintf(stderr, "USAGE: %s key\n", *argv);
		return 1;
	}
	while ((c = getchar()) != EOF)  {
		if (*cp == '\0')
			cp = argv[1];
		c ^= *cp++;
		putchar(c);
	}
	return 0;
}
