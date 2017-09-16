/*-- nobksp.c -- Remove backspaces from input, plus the characters
 * they backspace over.
 *
 * Mark Riordan   28 Sept 1992
 */

#include <stdio.h>

int
main(argc,argv)
int argc;
char *argv[];
{
	int ch, oldch=0;
		
	while(EOF != (ch = getchar())) {
		if(ch == '\010') {
			oldch = 0;
		} else {
			if(oldch)putchar(oldch);
			oldch = ch;
		}
	}
	if(oldch) putchar(oldch);
	return 0;			
}