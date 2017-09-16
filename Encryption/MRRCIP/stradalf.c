/*    program stradalf
 *
 *  program to create a cipher alphabet for a "straddling checkerboard"
 *  monoalphabetic cipher.
 *
 *  stradalf <inalf >outalf -s singlefile
 *
 *  Where:
 *    inalf	  has a string of 26 chars
 *    singlefile  contains a string of characters; the first
 *		  8 unique characters in this string are placed
 *		  at the beginning of the output string.
 *		  These should be high-frequency characters,
 *		  as they are the ones which have a single digit
 *		  as their ciphertext equivalent.
 *    outalf	  is the output stream, which consists of the first
 *		  8 unique characters of "singlefile", followed by
 *		  the rest of the contents of "inalf" (minus the 8
 *		  characters already included).
 *
 *
 *  the resultant cipher is written out as a string of 26 chars.
 *
 *  Written by Mark Riordan   10 July 1988
 */

#include "stdio.h"
#include "ctype.h"
#include "string.h"

#define FALSE 0
#define TRUE 1
#define MXKEY 80
#define MXALPHA 80
#define DEBUG 0

int nalpha = 26;
char alfary[MXALPHA] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
extern FILE *fopen();

main(argc,argv)
int argc;
char *argv[];
{
  char key[MXKEY];
  char single[10];
  FILE *singlefile;
  int nkey=0;
  int ch,ich;
  int narg;
  int j;
  int gotsingle = FALSE;
  int badarg = FALSE;
  char *chptr;

  /* Process the command line arguments.			     */

  for (narg=1; narg<argc; narg++) {
    if(strcmp(argv[narg],"-s")==0) {
      /* Start by finding it.					     */
      singlefile = fopen(argv[++narg],"r");
      if(!singlefile) {
	fputs("Cannot open the -s file.\n",stderr);
      }
      gotsingle = TRUE;
    } else {
      badarg = TRUE;
    }
  } /* end for narg */

  /* Check to see whether we got any bad arguments.		     */

  if(badarg | !gotsingle) {
    fputs("Usage:  stradalf <infile >outfile -s singlefile     \n",    stderr);
    fputs("  where infile  contains a mixed alphabet used as a key. \n", stderr);
    fputs("  singlefile  contains text which must have 8 unique    \n",stderr);
    fputs("	characters somewhere in the file.	       \n",    stderr);
    fputs("  outfile contains a cipher alphabet consisting of	  \n", stderr);
    fputs("	the first 8 unique characters in singlefile,	 \n",  stderr);
    fputs("	followed by the contents of infile (minus those chars).\n",stderr);
  } else {
    do {
      ch = fgetc(singlefile);
      if(ch == EOF) {
	fputs("The -s file does not contain 8 unique characters.\n",stderr);
	exit(1);
      }
      if(islower(ch)) ch = toupper(ch);
      for(j=0; j<nkey; j++) {
	if(ch == key[j] | !isprint(ch)) goto gotsingle;
      }
      key[nkey++] = ch;
  gotsingle:;
    } while(nkey < 8);

    while(EOF != (ch=getchar())) {
      if(islower(ch)) ch = toupper(ch);
      for(j=0; j<nkey; j++) {
	if(ch == key[j] | !isprint(ch)) goto gotlet;
      }
      key[nkey++] = ch;
     gotlet:;
    }

    for(j=0; j<nkey; j++) {
      putchar(key[j]);
    }
    putchar('\n');
  }
}
}
