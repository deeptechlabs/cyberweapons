/* Warning -- this code depends on things that happen to be
   true in 7-bit ASCII; it probably won't work right in
   other codesets.  The meaning of "rot13" in non-English
   alphabets isn't clear to me, so ISO-Latin1, e.g., may
   or may not be okay with this.  Codesets, such as EBCDIC,
   which have holes in the sequences for encoding alphabetics
   will have non-alphabetics shifted, but the rot13 will still
   work correctly for the alphabetics.  Codesets (such as
   Grey codes) which have non-sequential encodings for the
   alphabet won't work right at all, but I'm not sure that
   C is well defined in such environments anyway.
		--Ken Pizzini
		ken@halcyon.com
*/

/*
  ROT13 is a simple encryption program commonly found on UNIX
  systems.  In this cipher, A is replaced by N, B is replaced by O,
  etc.  Every letter is rotated thirteen places.  This is a simple
  substitution cipher.  
*/

#include <stdio.h>
#define OFFSET	('n' - 'a')

int
main()
{
	int c;

	while ((c = getchar()) !=EOF) {
		if ('a' <= c && c <= 'm' )
			c += OFFSET;
		else if ('A' <= c && c <= 'M' )
			c += OFFSET;
		else if ('n' <= c && c <= 'z' )
			c -= OFFSET;
		else if ('N' <= c && c <= 'Z' )
			c -= OFFSET;
		putchar(c);
	}
	return 0;
}
