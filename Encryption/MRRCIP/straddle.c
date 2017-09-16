/*  STRADDLE.C -- Implement a monoalphabetic "straddling matrix"
 *  cipher in which each input character is replaced by 1 or 2
 *  output characters.
 *
 *  Called as:
 *
 *  straddle <infile >outfile -k keyfile -d digitfile
 *
 *  Written by Mark Riordan    9 July 1988
 */

#define ALPHASIZE 26

#include "stdio.h"
#include "ctype.h"
#include "string.h"

char letters[ALPHASIZE+3];
char *plaptr;
char ciphertext[ALPHASIZE+3][3];

main(argc,argv)
int argc;
char *argv[];
{
  FILE *keyfile,*digitfile;
  extern FILE *fopen();
  int narg;
  int j;
  int badarg=0;
  char *singlechars;
  char *digptr, *stdoubleptr;
  int doubidx=0;
  int digidx=0;
  int id;
  int letidx;
  int cipidx;
  int slashidx;
  int ch;
  int outch;
  int numch;
  int numflag=0;
  int stop = 0;
  int gotsingle=0, gotkey=0, gotdigit=0, gotencip=0;
  int encip=0;
  int nletters=0, nsingles=8, ndigits=0, ncip=0;
  char digits[ALPHASIZE+3];

  /* Crack the command line. */

  for (narg=1; narg<argc; narg++) {
    if(strcmp(argv[narg],"-k")==0) {
      /* Got -k keyfile 					      */
      gotkey = 1;
      if( !(keyfile=fopen(argv[++narg],"r"))) {
	fputs("Cannot open key file.\n",stderr);
	stop = 1;
      }
    } else if(strcmp(argv[narg],"-d")==0) {
      gotencip = 1;
    } else if(strcmp(argv[narg],"-e")==0) {
      encip = 1;
      gotencip = 1;
    } else if(strcmp(argv[narg],"-t")==0) {
      /* Got -t digitfile		       */
      gotdigit = 1;
      if( !(digitfile=fopen(argv[++narg],"r"))) {
	fputs("Cannot open file containing digits.\n",stderr);
	stop = 1;
      }
    } else {
      badarg = 1;
    }
  } /* end for narg */

  if(badarg | !gotkey | !gotdigit) {
    fputs("Usage:  straddle<infile >outfile {-e|-d} -t digitfile -k keyfile\n",    stderr);
    fputs("  where:				  \n",		      stderr);
    fputs("  -e means encipher; -d means decipher.\n",	stderr);
    fputs("  digitfile contains the 10 digits in desired order.\n",    stderr);
    fputs("	The first 8 digits are used as single-digit equivalents\n",stderr);
    fputs("	for the first 8 characters of the key.\n", stderr);
    fputs("  keyfile contains the 26 letters of the key.   \n",        stderr);
  } else if(!stop) {

    /*
     * Command line was cracked OK.
     * Read the digits from the digitfile.
     */

    while(EOF != (ch=getc(digitfile))) {
      if(isprint(ch)) {
	digits[ndigits++] = ch;
      }
    }
    digits[ndigits] = '\0';
    if(ndigits != 10) {
      fputs("Number of digits is not 10. \n",stderr);
      stop = 1;
    }
    stdoubleptr = digits+8;
    digptr = stdoubleptr-1;

    /*
     *	Read the alphabet from the keyfile.
     *	Append to it the '/' (used to switch between numeric and
     *	alphabetic mode) and the '.'.
     */

    while(EOF != (ch=getc(keyfile)) && !stop) {
      if(isprint(ch)) {
	letters[nletters++] = islower(ch) ? toupper(ch) : ch;
      }
      if(nletters > ALPHASIZE) {
	fputs("Key has too many letters (>26).\n",stderr);
	stop = 1;
      }
    }
    slashidx = nletters;
    letters[nletters++] = '/';
    letters[nletters++] = '.';
    letters[nletters]	= '\0';

    /*
     *	Construct in "ciphertext" a list of the ciphertext equivalents
     *	for the corresponding elements of "letters".
     */

    for(ncip=0; ncip<nletters; ncip++) {
      cipidx = 0;
      if(ncip < nsingles) {
	ciphertext[ncip][cipidx++] = digits[digidx];
      } else {
	ciphertext[ncip][cipidx++] = *digptr;
	ciphertext[ncip][cipidx++] = digits[digidx];
      }
      ciphertext[ncip][cipidx] = '\0';
      digidx++;
      if(ncip % ndigits == nsingles-1) {
	digptr++;
	digidx = 0;
      }
    }

    /*
     *	Display the contructed table to the curious user.
     */

/*  for(j=0; j<ALPHASIZE+2; j++) {
      fputc(letters[j],stderr);  fputc('=',stderr);
      fputs(ciphertext[j],stderr);  fputc(' ',stderr);
      if(j==14) fputc('\n',stderr);
    }
    errch('\n');  */

    errch('\n');
    errch(' ');
    for(j=0; j<ndigits; j++) {
      errch(' ');  errch(digits[j]);
    }
    errch('\n');
    errch(' ');
    for(letidx=0; letidx<nsingles; letidx++) {
      errch(' ');  errch(letters[letidx]);
    }
    errch('\n');
    for(digidx=nsingles; digidx<ndigits; digidx++) {
      errch(digits[digidx]);
      for(j=0; j<ndigits; j++) {
	errch(' ');  errch(letters[letidx++]);
      }
      errch('\n');
    }
    if(encip) {
    /*
     *	Now encipher the input stream.	Handle plaintext digits by
     *	preceeding and following them with '/', and tripling
     *	each digit.
     */

      while((ch=getchar()) != EOF) {
	ch = islower(ch) ? toupper(ch) : ch;
	if(isdigit(ch)) {
	  if(!numflag) {
	    docip('/');
	    numflag = 1;
	  }
	  for(j=0; j<3; j++) docip(ch);
	} else {
	  if(numflag) {
	    docip('/');
	    numflag = 0;
	  }
	  docip(ch);
	}
      }  /* end while getchar */
    } else {   /* end of encipher */

      /*  Decipher the input. */

      while((ch=getchar()) != EOF) {
	if(isdigit(ch)) {
	  outch = '\0';
	  if(numflag) {
	    numflag++;
	    if(numflag == 2) {
	      numch = ch;
	    } else if(numflag == 3 && ciphertext[slashidx][0]==numch &&
	     ciphertext[slashidx][1]==ch) {
	      numflag = 0;
	    } else {
	      if(ch != numch) {
		outch = '!';
	      }
	      if(numflag >= 4) {
		outch = ch;
		numflag = 1;
	      }
	    }
	  } else if(doubidx) {
	    for(id=0; ch != digits[id]; id++);
	    outch = letters[id+doubidx];
	    doubidx = 0;
	  } else {
	    /* Check to see whether the digit is a single digit.  */
	    for(digptr = stdoubleptr; *digptr && ch!=*digptr; digptr++);
	    if(ch==*digptr) {
	    /* The digit is the first of a 2-digit sequence. */
	      doubidx = ndigits * (digptr-stdoubleptr) + nsingles;
	    } else {  /* Single digit. */
	      for(id=0; ch != digits[id]; id++);
	      outch = letters[id];
	    }  /* end if ch==*digptr */
	  } /* end if doubptr */
	  if (outch) {
	    if(outch == '/') {
	      numflag = numflag ? 0 : 1;
	    } else {
	      putchar(outch);
	    }
	  }
	}    /* end if isdigit */
       }  /* end while getchar */
    }
  }  /* end if badarg */
}

docip(ch)
int ch;
{
  plaptr = strchr(letters,ch);
  if(plaptr) {
    fputs(ciphertext[plaptr-letters],stdout);
  } else {
    putchar(ch);
  }
}

errch(ch)
int ch;
{
  fputc(ch,stderr);
}
}
