/*  SMPLSUB.C -- Simple substitution cipher.
 *
 *  Called as:
 *
 *  phrase -k cipalphafile <plaintext >ciphertext
 *
 *  -k	 specifies the name of a file containing the cipher alphabet.
 *	 There are 26 characters; the first character is the ciphertext
 *	 equivalent of the plaintext letter A, and so on.
 *	 Characters other than the 26 letters (upper and lower case)
 *	 are sent through untranslated.
 *
 *  -d	 specifies deciphering
 *  -e	 specifies enciphering
 *
 *  Written by Mark Riordan    30 Jan 1988  and 11 October 1988
 */

#define LINFILE 60
#define DEBUG 1
#define SIZEALPHA 26

#include "stdio.h"
#include "ctype.h"

extern FILE *fopen();
extern char *index();

main(argc,argv)
int argc;
char *argv[];
{
  char infile[LINFILE];
  FILE *instream;
  int narg;
  int j;
  int ch;
  int chidx;
  int gotkey=0, gotencip=0, err=0;
  char cipher[SIZEALPHA];
  char *plainalf = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  char *fromalf, *toalf;
  char outchar;

  for (narg=1; narg<argc; narg++) {
    if(strcmp(argv[narg],"-k")==0) {
      /* We have the file name in the next argument.		     */

      narg++;
      strcpy(infile,argv[narg]);
      gotkey = 1;
    } else if(strcmp(argv[narg],"-d")==0) {
      /* Decipher flag */
      fromalf = cipher;
      toalf = plainalf;
      gotencip = 1;
    } else if(strcmp(argv[narg],"-e")==0) {
      /* Encipher flag */
      fromalf = plainalf;
      toalf = cipher;
      gotencip = 1;
    } else {
      err = 1;
    }
  } /* end for narg */

  if(err | !gotkey | !gotencip) {
    fputs("Usage:  smplsub {-e|-d} -k cipalphafile <plaintext >ciphertext\n",stderr);
    fputs("  where cipalphafile has 26 characters--the cipher\n",stderr);
    fputs("	      equivalents of the 26 letters.\n",stderr);
    fputs("	   -d means decipher, -e means encipher.",stderr);
  } else {

    /* Open file containing cipher alphabet and read it into "cipher"*/

    instream = fopen(infile,"r");
    if(instream==NULL) {
      fprintf(stderr,"Cannot open input file %s",infile);
      exit(0);
    }
    for(j=0; (ch=fgetc(instream)) != EOF && (j<SIZEALPHA); j++) {
      cipher[j] = ch;
    }

    /* Now translate the input stream.				     */

    while(EOF != (ch=getchar())) {
      if(isalpha(ch)) {
	if(islower(ch)) ch = toupper(ch);
	chidx = myindex(fromalf,ch);
	outchar = (chidx >= 0) ? toalf[chidx] : ch;
      } else {
	outchar = ch;
      }
      putchar(outchar);
    }
  }
}

/*--- Function myindex --------------------------------------
 *
 *   Entry:   str is a zero-terminated string
 *	      ch  is a character (integer)
 *
 *   Exit:    Function value is the index of the first occurrence
 *	      of 'ch' in 'str' if found, else -1;
 */

int
myindex(str,ch)
char *str;
int ch;
{
  char *mystr;

  mystr = str;
  while(*mystr && *mystr!=ch) mystr++;
  if(! (*mystr)) {
    return(-1);
  } else {
    return(mystr-str);
  }
}
}
