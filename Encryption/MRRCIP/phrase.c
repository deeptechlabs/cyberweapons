/*  PHRASE.C -- Select a word or phrase from the input file.
 *  One or more complete words from the input file is selected randomly
 *  and written to standard output.
 *  Used for cryptographic purposes.
 *
 *  Called as:
 *
 *  phrase [-rmin] [-sseed] -f filename
 *
 *  -r	 specifies the maximum number of letters in
 *	 the phrase.  Spaces, if present in the input, are
 *	 written to the output but are not counted in the letter count.
 *	 Newlines are stripped and not counted.
 *	 Default for min is 7.
 *
 *  -f	 specifies the input file name.  (Standard input can't be
 *	 used because we must know the size of the file beforehand.)
 *
 *  -s	 specifies a random number seed used to help select the text.
 *
 *  Written by Mark Riordan    27 Jan 1988
 */

#define LINFILE 60
#define BEGORIGIN 0
#define ENDORIGIN 2
#define DEBUG 1
#define RANLOOPCT 21
#define MAXADD 11

#include "stdio.h"
#include "ctype.h"

extern int atoi();
extern long int ftell();
extern long int time();
extern FILE *fopen();
extern char *index();
extern long int lowprime();
extern long int myran();

long int ranmod,ranseed,ranmult;
int letmin=7, letmax=20;
int okdigits=0, okperiod=0;

main(argc,argv)
int argc;
char *argv[];
{
  long int filesize,seekpt;
  long int filepos;
  long int curtime;
  char infile[LINFILE];
  FILE *instream;
  int narg;
  int j;
  int gotargs=0;
  int result;
  char *thisarg;
  char *mptr;
  int addlen;
  int startseed = 543;

  for (narg=1; narg<argc; narg++) {
    if(strcmp(argv[narg],"-f")==0) {
      /* We have the file name in the next argument.		     */

      narg++;
      strcpy(infile,argv[narg]);
      gotargs = 1;
    } else if(strncmp(argv[narg],"-r",2) == 0) {
      /* Crack the min/max range.				     */

      thisarg = argv[narg]+2;
/*    mptr = index(thisarg,':');				     */
/*    if(mptr==NULL) {						     */
/*	fprintf(stderr,"Bad range parameter: %s\n",argv[narg]);      */
/*	gotargs = 0;						     */
/*    } else {							     */
	letmin = atoi(thisarg);
/*	letmax = atoi(mptr+1);					     */
/*    } 							     */

    } else if(strncmp(argv[narg],"-s",2) == 0) {
      /* Crack the seed number. 				     */
      thisarg = argv[narg]+2;
      startseed = atoi(thisarg);
    } else if(strcmp(argv[narg],"-p")==0) {
      /* Periods allowed.					     */
      okperiod = 1;
    } else if(strcmp(argv[narg],"-d")==0) {
      /* Digits allowed.					     */
      okdigits = 1;
    }
  } /* end for narg */

  if(!gotargs) {
    fprintf(stderr,"Usage:  phrase -f infile [-rmin] [-sseed] [-p] [-d] \n");
    fprintf(stderr,"  infile is the name of the input file of text\n");
    fprintf(stderr,"  min    is the minimum number of letters\n");
    fprintf(stderr,"	     in the desired selected phrase.\n");
    fprintf(stderr,"  seed   is an arbitrary number to help select text\n");
    fprintf(stderr,"  -p     means periods are OK in output\n");
    fprintf(stderr,"  -d     means digits  are OK in output\n");
  } else {
    instream = fopen(infile,"r");
    if(instream==NULL) {
      fprintf(stderr,"Cannot open input file %s",infile);
      exit(0);
    }
    result = fseek(instream,(long)0,ENDORIGIN);
    if(result!=0) {
      fprintf(stderr,"Cannot complete seek on input file.");
      exit(0);
    }
    filesize = ftell(instream);
    time(&curtime);
#if DEBUG > 1
    fprintf(stderr,"File size is %ld\n",filesize);
    fprintf(stderr,"Time is %ld\n",curtime);
    fprintf(stderr,"Range is %d:%d\n",letmin,letmax);
    {  long int j=0;
       for(;j>=0;) {
	fprintf(stderr,"Find prime <= what number? ");
	scanf("%ld",&j);
	printf("  %ld\n",lowprime(j));
      }
    }
#endif
    ranmod = lowprime(filesize - 5*letmin);
    ranmult = ranmod;
    do {
      ranmult = 3*ranmult/11 + inportb(0x40);
    } while (ranmult > 47000);
    ranmult = lowprime(ranmult);
    ranseed = curtime&0x03fff + ((curtime>>12)&0xfff) + startseed + inportb(0x40);
    for(j=0; j<RANLOOPCT; j++) {
#if DEBUG > 1
      printf("seed,mult,mod= %ld %ld %ld\n",ranseed,ranmult,ranmod);
#endif
      seekpt = myran();
    }
#if DEBUG > 1
    fprintf(stderr,"seekpt = %ld\n",seekpt);
#endif
    if(fseek(instream,seekpt,BEGORIGIN)) {
      puts("Cannot seek on input file.");
      exit(0);
    }

    letmin += myran() % MAXADD;
    getphrase(instream,&seekpt);
    fseek(instream,seekpt,BEGORIGIN);
    writephrase(instream);
  }
}
/* ----------------------------------------------------------------
 *
 *  Function lowprime(num)
 *
 *  Entry    num is a positive integer > 2
 *
 *  Exit     lowprime is the largest prime number <= num
 */
long
lowprime(num)
long num;
{
  long int testfact;

  for (;;num--) {
    if(2*(num/2) == num) goto endtest;
    for(testfact=3; testfact*testfact<=num; testfact +=2) {
      if(testfact*(num/testfact) == num) goto endtest;
    }
    return(num);
  endtest: ;
  }
}
/* -----------------------------------------------------------
 *
 *  Function myran()
 *
 *  Entry:  ranmod, ranseed, ranmult are the 3 elements of a
 *	    standard linear congruential random number generator.
 *
 *  Exit:   myran and ranseed are the next number in the sequence.
 */
long int
myran()
{
  ranseed = ((ranseed*ranmult) % ranmod);
  while(ranseed < 0) {
#if DEBUG > 1
    printf("in myran, ranseed < 0; %ld\n",ranseed);
#endif
    ranseed += ranmod;
  }
  return(ranseed);
}
/* ---------------------------------------------------------------------
 *
 *  Function getphrase(instream,seekpt)
 *
 *  Entry:  instream is a stream which has been positioned to
 *		     a random place from which we wish to begin
 *		     taking a phrase.
 *	    seekpt   is the current file position.
 *
 *  Exit:   seekpt   is the place where a valid phrase starts.
 */
getphrase(instream,seekpt)
FILE *instream;
long *seekpt;
{
#define LINELIMIT 65

  int linechars=0;
  int nchars=0;
  int keepgo=1;
  int ch;

  do {
    ch = agetc(instream);
  } while (ch != ' ');

  do {
    ch = agetc(instream);
    if(ch == '\n') {
    } else if(ch == ' ') {
      if(nchars >= letmin) {
	keepgo = 0;
      }
    } else if(isalpha(ch)) {
      nchars++;
    } else if(okdigits && isdigit(ch)) {
      nchars++;
    } else if(okperiod && ch=='.') {
      nchars++;
    } else {
      /*  Bad character--start over.				     */
      *seekpt = ftell(instream);
#if DEBUG > 0
    fprintf(stderr,"Found bad char %c at nchars=%d  seekpt now=%ld.\n",
      ch,nchars,*seekpt);
#endif
      nchars = 0;
    }
  } while (keepgo);
}
/* ---------------------------------------------------------------------
 *
 *  Function writephrase(instream)
 *
 *  Entry:  instream is a stream which has been positioned to
 *		     a random place from which we wish to begin
 *		     taking a phrase.
 *
 *  Exit:   The phrase has been written to output.
 */
writephrase(instream)
FILE *instream;
{
#define LINELIMIT 65

  int linechars=0;
  int nchars=0;
  int keepgo=1;
  int ch;

  do {
    ch = getc(instream);
  } while (ch != ' ');

  do {
    ch = agetc(instream);
    if(ch == '\n') {
      putchar(' ');
    } else if(ch == ' ') {
      if(nchars >= letmin) {
	keepgo = 0;
      } else if(linechars > LINELIMIT) {
	putchar('\n');
	linechars = 0;
      } else {
	putchar(' ');
	linechars++;
      }
    } else {
      linechars++;
      nchars++;
      putchar(ch);
    }
  } while (keepgo);
}
}
