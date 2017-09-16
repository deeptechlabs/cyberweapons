/*--- VIGKEY.C -- Program to make a numerical ordinal key
 *  from an input phrase.
 *
 *  Very simple:  output a list of ordinal numbers that corresponds
 *  to the input key, where A=0, B=1, etc.
 *
 *  Use with PERIODIC.C
 *
 *  Mark Riordan  19 Jan 1991
 */

static char author[] =
"Mark Riordan  1100 Parker  Lansing MI	48912";

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>

main(argc,argv)
int argc;
char *argv[];
{
   int ch,myord;
   char line[80];

   if(argc > 1) {
      fputs("vigkey -- Program to create a numeric (ordinal) key\n",stderr);
      fputs("  from an input phrase.\n",stderr);
      fputs("Usage:  vigkey <phrasefile >numericfile\n",stderr);
      exit(1);
   } else {
      while(EOF != (ch=getchar())) {
	 if(isprint(ch)) {
	    if(islower(ch)) ch = toupper(ch);
	    myord = ch - 'A';
	    itoa(myord,line,10);
	    fputs(line,stdout);
	    putchar(' ');
	 }
      }
   }
}
}
