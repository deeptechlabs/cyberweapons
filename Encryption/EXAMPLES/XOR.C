/* Corrected declaration of cp (old declaration won't work
   unless sizeof(int)==sizeof(char), which is almost never the case).
		--Ken Pizzini
		ken@halcyon.com
*/
/*
  SIMPLE XOR
*/

/* Usage:  crypto-xor key input_file output_file  */

#include <stdio.h>

int
main(int argc, char *argv[])
{
	FILE *fi, *fo;
	char *cp;
	int c;

	if ((cp = argv[1]) && *cp!='\0') {
		if ((fi = fopen(argv[2], "rb")) != NULL)  {
			if ((fo = fopen(argv[3], "wb")) != NULL)  {
				while ((c = getc(fi)) != EOF)  {
					if (*cp == '\0')
						cp = argv[1];
					c ^= *cp++;
					putc(c, fo);
				}
				fclose(fo);
			}
			fclose(fi);
		}
	}
	return 0;
}
