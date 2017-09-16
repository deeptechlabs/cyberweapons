/*  entran.c
 *  Program to encipher using columnar transposition.
 *
 *  Usage:   entran <plainfile >cipfile -f keyfile
 *
 *  plainfile contains the plaintext input.
 *	      Blanks are stripped from the input, but no other modifications
 *	      are made.  cf. the program BLOCK5 to "condition" the input.
 *  cipfile   contains the transposed (enciphered) output.han 80 total
 *  keyfile   contains the key in numeric form.  It is a series of decimal
 *	      numbers.	The first number is the column number of the first
 *	      column to extract for the ciphertext, the second number specifies
 *	      the second column, etc.  Note that this is an "inverted" form
 *	      of the usual manner in which transposition keys are specified
 *	      for manual methods.
 *
 *  Written by Mark Riordan	       29 September 1986   (/mrr in FORTRAN)
 *  Converted to C			1 February  1988   (/mrr)
 *  New Algorithm (memory management)	6 February  1988   (/mrr)
 *
 *  This version does not use a 2-dimensional matrix--at least not
 *  in the obvious, straightforward way.  Instead, it allocates one
 *  row (line) of the matrix at a time, dynamically.  This way, the
 *  program only uses as much memory as it needs, and more importantly,
 *  it can process input files up to the full size of memory (when
 *  using large memory model).	(Relevant for PC version.)
 */
#include "stdio.h"

      int nplain,NPLAMX,NLNMAX,j,nkymax,lstrow;
static char copyright[] =
{"Copyright (C) 1988, by Mark Riordan  1100 Parker  Lansing MI	48912.\n"};
static char oktouse[] =
{"Non-commercial usage/distribution encouraged."};

FILE *keystream;
extern FILE *fopen();
extern char *malloc();

#define NPLAMX 8000
#define NLNMAX 80
#define NKYMAX 60
#define TRUE 1
#define FALSE 0
#define DEBUG 0

typedef struct linestruct {
  struct linestruct *nextln;
  char line[];
} TYPLINE, *LINEPTR;

LINEPTR firstlineptr;

main(argc,argv)
int argc;
char *argv[];
{
  int nchars,nkey,irow,ikey,icol,nrow,iline,curpos;
  int gotargs=FALSE,badarg=FALSE,block5=FALSE;
  int  wrtlim=60;
  int key[NKYMAX];
  char line[NLNMAX];
  int narg;
  int ch;
  int scanfres;
  int charsinline;
  int nrows=0;
  LINEPTR curlineptr,oldlineptr;

  /* Process the command line arguments.			     */

  for (narg=1; narg<argc; narg++) {
    if(strcmp(argv[narg],"-k")==0) {
      /* We have the file name in the next argument.		     */

      narg++;
      keystream = fopen(argv[narg],"r");
      if(keystream==NULL) {
	fputs("Cannot open key file.",stderr);
	badarg = TRUE;
      } else {
	gotargs = TRUE;
      }
    } else if(strcmp(argv[narg],"-5")==0) {
      /* Separate into blocks of 5				     */
      block5 = TRUE;
    } else {
      badarg = TRUE;
    }
  } /* end for narg */

  /* Check to see whether we got all required arguments, and	     */
  /* didn't get any bad arguments.				     */

  if(badarg || !gotargs) {
    fputs("Usage:  entran  <infile >outfile -k keyfile	       \n",    stderr);
    fputs("  where outfile contains the input text enciphered	  \n", stderr);
    fputs("  in classic columnar tranposition.			  \n", stderr);
    fputs("  -k specifies the key input file:  this file contains a\n",stderr);
    fputs("	series of column numbers in the order in which \n",    stderr);
    fputs("	they are to be taken off vertically.  The number \n",  stderr);
    fputs("	of columns can also be determined from this.	 \n",  stderr);
  } else {

/*  Read in the keys. */

    nkey = 0;
    do {
      scanfres = fscanf(keystream,"%d",&(key[nkey]));
      if(scanfres == 0 || scanfres == EOF ) break;
#if DEBUG > 2
  printf("key[%d] = %d\n",nkey,key[nkey]);
#endif
      nkey++;
    } while(TRUE);

    /*	Read in all of the plaintext, allocating buffers for it      */
    /*	as we go.  Each buffer holds one row's worth--that is,	     */
    /*	one character for each number in the key.		     */

    nchars = 0;
    firstlineptr = (LINEPTR) malloc(sizeof(TYPLINE)+nkey);
    nrows++;
    firstlineptr->nextln = NULL;
    oldlineptr = firstlineptr;
    curlineptr = firstlineptr;
    charsinline = 0;
    while((ch=getchar()) != EOF) {
      if(ch !=	' ' && ch != '\n') {

	/* If we overflowed the last line, time to allocate	     */
	/* another line.					     */

	if(charsinline >= nkey) {
	  curlineptr = (LINEPTR) malloc(sizeof(TYPLINE)+nkey);
	  nrows++;
	  if(!curlineptr) {
	    fputs("Unable to allocate enough memory.",stderr);
	    goto endit;
	  }
	  curlineptr->nextln = NULL;
	  oldlineptr->nextln = curlineptr;
	  oldlineptr = curlineptr;
	  charsinline = 0;
	}
	curlineptr->line[charsinline++] = ch;
	nchars++;
      }
    }

/*  We have read in all the text. */

#if DEBUG

/* Print out the entire matrix, by rows, for debugging purposes. */
  {
    LINEPTR ptr;
    int ich,il=0;

    printf("nrows=%d\n",nrows);
    ptr=firstlineptr;
    do {
      printf("%d: ",++il);
      for(ich=0; ich<nkey; ich++) putchar(ptr->line[ich]);
      putchar('\n');
      ptr = ptr->nextln;
    } while(ptr != NULL) ;
    puts("\nDone with printing out matrix.\n");
  }
#endif

    /* Take off the text by columns, placing it into "line"	     */
    /* and then writing it from there.				     */

    lstrow = nchars % nkey;
    if(lstrow == 0) lstrow = nkey;
    iline = 0;
    for(ikey = 0; ikey<nkey; ikey++) {
      icol = key[ikey] - 1;

      /* For this column (icol), read off one character from	     */
      /* each row, except possibly the last.			     */
      /* After placing each character in the output line, check      */
      /* to see if we've filled the line.			     */

      for(curlineptr=firstlineptr, irow=0;
       irow<nrows-1 || (irow==nrows-1 && icol<=lstrow-1);
       curlineptr=curlineptr->nextln, irow++) {
	line[iline] = curlineptr->line[icol];
	iline++;
	if(iline >= wrtlim) flush(line,&iline);
      }
    }
    flush(line,&iline);
  }
endit: ;
}
/* --- Function flush(line,iline) --------------------------------------
 *
 *  Subroutine to flush the current output line to disk.
 *
 *    entry   line    is the current output line.
 *	      iline   is the number of characters in line.
 *
 *    exit    The line has been written out.
 *	      iline   is zero to reflect this fact.
 */
flush(line,iline)
char line[];
int *iline;
{
      int j;

      for(j=0; j<*iline; j++) putchar(line[j]);
      if(*iline >= 0) putchar('\n');
      *iline = 0;
}
}
