/*    program mkmnal
 *
 *  program to create a monoalphabetic cipher alphabet given a
 *  key phrase input by the user.
 *  the resultant cipher is written out as a string of 26 chars
 *  on *.  (char 1 = ciphertext for 'a', etc.)
 *
 *  mark riordan - march 19, 1982
 *  Revised 30 January 1988.	      /mrr
 *  Converted to C 15 February 1988.  /mrr
 */

#include "stdio.h"
#include "ctype.h"

#define FALSE 0
#define TRUE 1
#define MXKEY 80
#define MXALPHA 80
#define DEBUG 0

int nalpha = 26;
char alfary[MXALPHA] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

main(argc,argv)
int argc;
char *argv[];
{
char keyary[MXKEY], monary[MXALPHA];
char keyinp[MXKEY];
  int ch,ich;
  int narg;
  int ninch = 0;
  int badarg = FALSE;
  char *chptr;

  /* Process the command line arguments.			     */

  for (narg=1; narg<argc; narg++) {
    if(strcmp(argv[narg],"-j")==0) {
      /* Remove the letter J from the alphabet. 		     */
      /* Start by finding it.					     */

      for(chptr=alfary; (*chptr) != 'J'; chptr++);
      for(;*chptr ; chptr++) {
	*chptr = *(chptr+1);
      }
      nalpha--;
    } else {
      badarg = TRUE;
    }
  } /* end for narg */

  /* Check to see whether we got any bad arguments.		     */

  if(badarg) {
    fputs("Usage:  mrrmkmon <infile >outfile [-j]	       \n",    stderr);
    fputs("  where infile  contains a phrase to be used as a key. \n", stderr);
    fputs("  outfile contains a cipher alphabet.		  \n", stderr);
    fputs("  -j specifies that the letter J is not to be included  \n",stderr);
    fputs("	in the output cipher alphabet.		       \n",    stderr);
    fputs("							 \n",  stderr);
  } else {

    while((ch=getchar()) != EOF) {
      if(ch != '\n') {
	keyary[ninch++] = ch;
      }
    }
    keyary[ninch] = '\0';

    makmon(keyary,monary);
    for(ich=0; ich<nalpha; ich++) {
      putchar(monary[ich]);
    }
    putchar('\n');
  }
}
/*
 *    subroutine makmon(keyary,monary)
 *
 *  subroutine to make a monoalphabetic cipher alphabet based on a
 *  keyphrase.
 *
 *  keyary(i)  - input array of characters comprising the key.
 *		 duplicate chars are allowed, but all chars must
 *		 be alphabetic.
 *  keylen     - number of chars in above array.
 *  monary(i)  - output array containing the cipher alphabet.
 *		 contains the ciphertext for each letter of the
 *		 alphabet in order.
 *
 *  how it works:
 *
 *  a grid is made with the first row being the keyphrase, with blanks
 *  substituted for the second and subsequent occurrences of each
 *  letter in the phrase.   the second and following rows (if any)
 *  consist of the rest of the alphabet in alphabetical order.
 *  thus, the grid contains each letter of the alphabet exactly once
 *  (and probably some blanks as well).
 *  the cipher alphabet is obtained by reading off the columns of
 *  the grid in order 0 thru ncol-1, ignoring blanks.
 */
makmon(inary,monary)
char inary[],monary[];
{

  char table[MXALPHA][MXALPHA];
  char keyary[MXALPHA];
  int  qused[MXALPHA];
  int  keylen,inlen;
  int  ich,icol,irow,jcol,jrow,ikeych,ncol,nrow,currow,curcol;
  int  ialfch;
  int  curmon;

  inlen = strlen(inary);
  if(inlen > nalpha) {
    fputs("Key too long for this version.\n",stderr);
  }
#if DEBUG
  printf("In makmon, nalpha=%d, inary=%s\n",nalpha,inary);
#endif
  rmnalf(inary,inlen,keyary,&keylen);
#if DEBUG
  printf("keylen=%d keyary=%s\n",keylen,keyary);
#endif

  for(ich=0; ich<nalpha; ich++) {
    qused[ich] = FALSE;
  }
  for(irow = 0; irow<nalpha; irow++) {
    for(icol = 0; icol<nalpha; icol++) {
      table[irow][icol] = ' ';
    }
  }

/*  fill in the first row of the table with the key, replacing any
 *  duplicate letters in the key with ' '.
 */

  jcol = 0;
  for(ikeych = 0; ikeych<keylen; ikeych++) {
    if(!qused[ordch(keyary[ikeych])]) {
      table[0] [ikeych] = keyary[ikeych];
      qused[ordch(keyary[ikeych])] = TRUE;
      jcol++;
    }
  }

/*  Compute the number of rows and columns.
 *  This is a little tricky because the first row might not
 *  be completely filled in.
 */

  ncol = keylen;
/*nrow = ((nalpha-jcol+ncol-1) / ncol) + 1 */
  nrow = ((nalpha-jcol+ncol-1) / ncol) + 1;

/*
 *  fill in the rest of the table with the alphabet sequentially,
 *  omitting duplicates, of course.
 */

  currow = 1;
  curcol = 0;

  for(ialfch = 0; ialfch<nalpha; ialfch++) {
    if(!qused[ialfch]) {
      table[currow][curcol] = alfary[ialfch];
      qused[ialfch] = TRUE;
      curcol++;
      if(curcol >= ncol) {
	curcol = 0;
	currow++;
      }
    }
  }

/*  for debugging purposes, print the table. */

#if DEBUG
  printf("nrow=%d  ncol=%d\n",nrow,ncol);
  for(irow=0; irow < nrow; irow++) {
    for(icol=0; icol<ncol; icol++) putchar(table[irow][icol]);
    putchar('\n');
  }
#endif

/*
 *  now, take off the columns of the table sequentially (0 - ncol-1).
 */
  curmon = 0;
  for(curcol = 0; curcol<ncol; curcol++) {
    for(currow = 0; currow<nrow; currow++) {
      if(table[currow][curcol] != ' ') {
	monary[curmon] = table[currow][curcol];
	curmon++;
      }
    }
  }
#if DEBUG
  printf("curmon=%d\n",curmon);
#endif

  if(curmon != nalpha) {
    puts("in makmon, curmon <> nalpha",stderr);
  }
}
/* --- Function ordch(ch) ----------------------------------------------
 *
 *   Entry   ch     is a character
 *	     alfary is the character set
 *	     nalpha is the number of characters in alfary.
 *
 *   Exit    ordch  is an integer corresponding to the position of
 *		    the character in the program's character set.
 *		    (This would normally be the letters A-Z, not
 *		    the ASCII character set).
 *		    -1 if not found.
 */

int
ordch(ch)
char ch;
{
  int chpos;

  for(chpos=0; chpos<nalpha; chpos++) {
    if(alfary[chpos] == ch) {
      return(chpos);
    }
  }
  return(-1);
}
/* --- Function qalpha(ch) ---------------------------------------------
 *
 *   Entry
 */
int
qalpha(ch)
char ch;
{
  int chpos;

  if(ordch(ch) >= 0) {
    return(TRUE);
  } else {
    return(FALSE);
  }
}
/* --- Function rmnalf(strin,aryout,lenout -------------------------------
 *  make a copy of a string of characters, removing any non-alphabetics.
 *
 *  strin     - input string of characters
 *  aryout(j) - output array of only alphabetic chars
 *  lenout    - output number of chars in above array
 */

rmnalf(strin,lenin,aryout,lenout)
char *strin,*aryout;
int lenin;
int *lenout;
{
  int ich;
  char ch;

  *lenout = 0;
  for(ich = 0; ich<lenin; ich++) {
    ch = strin[ich];
    if(islower(ch)) ch = toupper(ch);
    if(qalpha(ch)) {
      aryout[*lenout] = ch;
      (*lenout)++;
    }
  }
  aryout[*lenout] = '\0';
}
}
