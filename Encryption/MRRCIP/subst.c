#include "stdio.h"
#include "ctype.h"
/*  SUBST.C
 *  Program to aid in solving monoalphabetic substitution ciphers.
 *  The program displays a ciphertext on the screen and allows
 *  the user to make guesses as to what each of the ciphertext
 *  characters stands for.  The full-screen orientation allows
 *  you to play "what if" easily, because the effect of a guess
 *  ("What if I say that the ciphertext X stands for D?") is seen
 *  instantly on the screen.
 *
 *  Called as:	subst <ciptext -o outplainfile [-a alphafile]
 *     Note:  -a not implemented fully
 *
 *  Mark Riordan   31 July 1987
 *  Revised  30 Jan 1988
 */

#define MAXLINES 9
#define MAXCOLS  80
#define PLAINLINE 20
#define CIPLINE   19
#define FREQLINE 21
#define DILINE	 22
#define DUPLINE  23
#define NUMDUPLINES  2
#define BEGCIPSCRLINE 0
#define BEGPLAINSCRLINE 1
#define SIZEALPHA 28
#define MAXDI 600
#define MAXASCII 256
#define CTRLZ	26
#define LEFT	(75+128)
#define RIGHT	(77+128)
#define TAB 9
#define TABINC 5
#define MIDCHAR 41
#define FALSE 0
#define TRUE 1
#define DEBUG 1

typedef struct distruct {
  char di[2];
  int  count;
} TYPDIGRAPH, *TYPDIPTR;

char plain[MAXLINES][MAXCOLS];
char   cip[MAXLINES][MAXCOLS];
char alphaplain[SIZEALPHA];
char   alphacip[SIZEALPHA];
char   tranc2p[MAXASCII];
char   tranp2c[MAXASCII];
struct typfreq {
  char chval;
  int chcount;
} freq[MAXASCII];
int nlines=0;
int curtrancol=0, curkey=0;
int gotoutfile=FALSE;
int gotalphafile=FALSE;
int gotdupfile=FALSE;
FILE *outfile, *fopen(), *alphafile, *dupfile;
char *fgets();
extern char *malloc();
int totalpha=0;
int ndigraphs=0;

main(argc,argv)
int argc;
char *argv[];
{
  int j,jcol,jrow,jline,ch,ncols,iline,icol;
  int narg;
  int gotargs=0;
  int qerror=FALSE;
  char lastch;
  TYPDIPTR diarray[MAXDI];

  for (narg=1; narg<argc && !qerror; narg++) {
    if(strcmp(argv[narg],"-o")==0) {
      /* We have the output file name in the next argument.	     */

      narg++;
      outfile = fopen(argv[narg],"w");
      if(outfile == 0) {
	puts("Unable to open output file.");
	goto endit;
      } else {
	gotoutfile = TRUE;
      }
      gotargs = TRUE;
    } else if(strcmp(argv[narg],"-a")==0) {
      /* We have the alphabet file name in the next argument.	       */

      narg++;
      alphafile = fopen(argv[narg],"rw");
      if(alphafile == 0) {
	puts("Unable to open alphabet file.");
	goto endit;
      } else {
	gotalphafile = TRUE;
      }
    } else if(strcmp(argv[narg],"-d")==0) {
      /* We have the name of the file with dups as the next argument.*/

      narg++;
      dupfile = fopen(argv[narg],"r");
      if(dupfile == 0) {
	fputs("Unable to open file with duplicates.");
	goto endit;
      } else {
	gotdupfile = TRUE;
      }
    } else {
      qerror = TRUE;
    }
  } /* end for narg */

  if(!gotargs || qerror) {
    fputs("Usage:  subst -o outplain [-a alphafile] [-d dupfile] <inciptext\n",stderr);
    fputs("  where outplain is the name of the output file of text\n", stderr);
    fputs("  inciptext is the input file of ciphertext\n",	       stderr);
    fputs("  dupfile   is output from 'dups'\n",		       stderr);
/*  fputs("  alphafile is the in/out file of suggested mapping\n",     stderr);*/
/*  fputs("    (Line 1 has plain alphabet; line 2 suggested cipher)\n",stderr);*/
    fputs("  Terminate via CTRL-Z.",				       stderr);
    goto endit;
  }

/* Initialize plain and cip arrays to blanks.				*/

  for (jline=0; jline<MAXLINES; jline++) {
    for (jcol=0; jcol<MAXCOLS; jcol++) {
      plain[jline][jcol] = ' ';
      cip[jline][jcol]	 = ' ';
    }
  }

  for(j=0; j<MAXASCII; j++) {
    tranc2p[j] = ' ';
    tranp2c[j] = ' ';
    freq[j].chcount = 0;
    freq[j].chval = j;
  }

  strncpy(alphacip,"ABCDEFGHIJKLMNOPQRSTUVWXYZ,(",SIZEALPHA);
  for (j=0; j<SIZEALPHA; j++) {
    alphaplain[j] = ' ';
  }

/* Read in plaintext.							*/

  jline = 0;
  jcol = 0;
  lastch = '\0';
  while(EOF != (ch=getchar())) {
    if(ch == '\n') {
      jcol = 0;
    } else {
      if(jcol==0 && jline<MAXLINES) {
	jline++;
	nlines++;
      }
      cip[jline-1][jcol] = ch;
      if(isalpha(ch)) {
	freq[ch].chcount++;
	totalpha++;
	if(lastch) {
	  countdi(lastch,ch,diarray,&ndigraphs);
	}
	lastch = ch;
      }
      if(jcol<MAXCOLS) jcol++;
    }
  }

/* Display ciphertext.							*/

  mclear();
  dofreq();
  dodi(diarray,ndigraphs);
  if(gotdupfile) dodup();
  showcip();
  gotoscr(PLAINLINE,0);

/* Loop, reading keyboard and taking action.			*/

  while(CTRLZ != (curkey = mgetch()) ) {
    if(curkey == LEFT) {
      curtrancol = curtrancol <= 0 ? curtrancol : curtrancol-1;
      gotoscr(PLAINLINE,curtrancol);
    } else if(curkey == RIGHT) {
      if(curtrancol < SIZEALPHA) {
	curtrancol++;
	gotoscr(PLAINLINE,curtrancol);
      }
    } else if(curkey == TAB) {
#ifdef WEIRDTAB
      for(j=curtrancol+1 % SIZEALPHA; j!=curtrancol; j = (j+1)%SIZEALPHA) {
	if(alphaplain[j] != ' ') {
	  curtrancol = j;
	  gotoscr(PLAINLINE,curtrancol);
	  break;
	}
      }
#endif
      curtrancol = curtrancol + TABINC;
      if(curtrancol >= SIZEALPHA) curtrancol = 0;
      gotoscr(PLAINLINE,curtrancol);
    } else if(curkey>0 & curkey<127 ) {

      /* This is where the real work is done.  The user has hit      */
      /* a key indicating the plaintext letter he wants to	     */
      /* substitute for the ciphertext letter the cursor is under.   */
      /* First, make sure that this plaintext letter is not already  */
      /* being used for some other ciphertext letter; if it is,      */
      /* erase those other instances.				     */

      if(curkey != ' ') {
	for(icol=0; icol<SIZEALPHA; icol++) {
	  if(alphaplain[icol] == curkey) {
	    makesub(' ',icol);
	  }
	}
      }
      makesub(curkey,curtrancol);
      showtranline();
      gotoscr(PLAINLINE,curtrancol);
    }
  }

/* Write output results.					*/

  if(gotoutfile) {
    for(iline=0; iline<nlines; iline++) {
      for(ncols=MAXCOLS-1; ncols>=0; ncols--) {
	if(plain[iline][ncols] != ' ') break;
      }
      for(icol=0; icol<=ncols; icol++) {
	putc(plain[iline][icol],outfile);
      }
      fputs("\n",outfile);
    }
    fclose(outfile);
  }

endit: ;
}

showcip()
{
  int cipcol,cipline,scrline,icol;

  scrline = BEGCIPSCRLINE;
  for (cipline=0; cipline<nlines; cipline++) {
    gotoscr(scrline,0);
    scrline += 2;
    for (cipcol=0; cipcol<MAXCOLS; cipcol++) {
      mputc(cip[cipline][cipcol]);
    }
  }

  gotoscr(CIPLINE,0);
  for(icol=0; icol<SIZEALPHA; icol++) {
    mputc(alphacip[icol]);
  }

}
/* -------------------------------------------------------------------
 *
 */

showtranline()
{
  int icol,ich;

  gotoscr(PLAINLINE,0);
  meol();

  for(icol=0; icol<SIZEALPHA; icol++) {
    mputc(alphaplain[icol]);
  }

  gotoscr(PLAINLINE,MIDCHAR);
  for(ich=0; ich<MAXASCII; ich++) {
    if(tranp2c[ich] != ' ' && ich!=' ') {
      mputc(ich);
    }
  }
  gotoscr(CIPLINE,MIDCHAR);
  meol();
  for(ich=0; ich<MAXASCII; ich++) {
    if(tranp2c[ich] != ' ' && ich!=' ') {
      mputc(tranp2c[ich]);
    }
  }

}

/* --------------------------------------------------------------------
 *
 */

dotran(curtrancol)
int curtrancol;
{
  int iline, icol;
  int lookcip, newplain;

  lookcip = alphacip[curtrancol];
  newplain = alphaplain[curtrancol];
  for(iline=0; iline<nlines; iline++) {
    for(icol=0; icol<MAXCOLS; icol++) {
      if(cip[iline][icol] == lookcip) {
	plain[iline][icol] = newplain;
	gotoscr(BEGPLAINSCRLINE+2*iline,icol);
	mputc(newplain);
      }
    }
  }
}

/* ----------------------------------------------------------------
 *
 *  Function makesub(ch,whichcol)
 *
 *  Substitute the (proposed) plaintext character "ch" for the
 *  ciphertext character at column "whichcol".
 *
 */
makesub(ch,whichcol)
char ch;
int whichcol;
{
      tranp2c[alphaplain[whichcol]] = ' ';
      alphaplain[whichcol] = ch;
      tranc2p[alphacip[whichcol]] = ch;
      tranp2c[curkey] = alphacip[whichcol];
      dotran(whichcol);
}

/* -----------------------------------------------------------------
 *
 *  Function freqcmp
 *
 *  Qsort comparison function for dofreq.
 *
 *  Entry
 *
 *  Exit
 */
freqcmp(a,b)
struct typfreq *a,*b;
{
  if((*a).chcount < (*b).chcount) {
    return(1);
  } else if((*a).chcount == (*b).chcount) {
    return(0);
  } else {
    return(-1);
  }
}

/* -----------------------------------------------------------------
 *
 *  Function dofreq
 *
 *  Entry  freq has character frequency information
 *
 *  Exit   Frequency information has been displayed on the screen.
 */
dofreq()
{
  int j;

  qsort(freq,MAXASCII,sizeof(freq[0]),freqcmp);
  gotoscr(FREQLINE,0);
/*
 *printf("Freq per 1000:");
 *for(j=0; j<10; j++) {
 *  printf(" %c=%d",freq[j].chval,(int)((long)1000*freq[j].chcount/totalpha));
 *}
 */
  printf("Singles:");
  for(j=0; j<12; j++) {
    printf(" %c=%d",freq[j].chval,freq[j].chcount);
  }
}

/* ---------------------------------------------------------------------
 *
 *  Function countdi(ch1,ch2,diarray,ndigraphs)
 *
 */
countdi(ch1,ch2,diarray,ndigraphs)
char ch1,ch2;
TYPDIPTR diarray[];
int *ndigraphs;
{
  int idi;
  int found=FALSE;

  for(idi=0; !found && idi<*ndigraphs; idi++) {
    if((diarray[idi])->di[0]==ch1 && diarray[idi]->di[1]==ch2) {
      diarray[idi]->count++;
      found = TRUE;
      break;
    }
  }
  if(!found) {
    diarray[*ndigraphs] = (TYPDIPTR) malloc(sizeof(TYPDIGRAPH));
    if(diarray[*ndigraphs] == NULL) {
      fputs("Cannot allocate sufficient memory for digraphs.\n",stderr);
    } else {
      idi= (*ndigraphs)++;
      diarray[idi]->di[0] = ch1;
      diarray[idi]->di[1] = ch2;
      diarray[idi]->count = 1;
    }
  }
#if DEBUG >2
  printf("In countdi, ch1=%c, ch2=%c, idi=%d, di=%c%c, count=%d\n",ch1,ch2,idi,
   diarray[idi]->di[0],diarray[idi]->di[1],diarray[idi]->count);
#endif
}

/* -----------------------------------------------------------------
 *
 *  Function dicmp
 *
 *  Qsort comparison function for dodi.
 *
 *  Entry
 *
 *  Exit
 */
dicmp(a,b)
TYPDIPTR *a,*b;
{
  if((*a)->count < (*b)->count) {
    return(1);
  } else if((*a)->count == (*b)->count) {
    return(0);
  } else {
    return(-1);
  }
}

/* -----------------------------------------------------------------
 *
 *  Function dodi
 *
 *  Entry
 *
 *  Exit   Frequency information has been displayed on the screen.
 */
dodi(diarray,ndigraphs)
TYPDIPTR diarray[];
int ndigraphs;
{
  int j;

  qsort(diarray,ndigraphs,sizeof(diarray[0]),dicmp);
  gotoscr(DILINE,0);
/*
 *printf("Freq per 1000:");
 *for(j=0; j<10; j++) {
 *  printf(" %c=%d",freq[j].chval,(int)((long)1000*freq[j].chcount/totalpha));
 *}
 */
  printf("Digraphs:");
  for(j=0; j<12; j++) {
    printf(" %c%c=%d",diarray[j]->di[0],diarray[j]->di[1],
     diarray[j]->count);
  }
}

/* ---------------------------------------------------------------------
 *
 *  Function dodup -- Display on screen the longest runs of duplicated
 *		      characters in the ciphertext.
 *
 *  Entry   dupfile  is the stream with the file of duplicates.
 *		     Each line of the file has the form:
 *		     size  freq  :xxxx
 *		     Where size  is the number of characters in the
 *				 duplicated string
 *
 *  Exit
 */
dodup()
{
  int dsize,dfreq;
  int dline=-1, dcol=9999;
  int takeschars;
  int gotmore=TRUE;
  char inline[MAXCOLS];
  char outbuf[MAXCOLS];
  char *lptr;
  int ich;

  while(fgets(inline,MAXCOLS,dupfile) && gotmore) {
    sscanf(inline,"%d%d",&dsize,&dfreq);

    /* Search for the colon which marks the beginning of the string. */

    for(lptr=inline; *lptr!=':'; lptr++);

    /* Skip to the next line if it won't fit on this one.	     */

    takeschars = dsize+2;
    while(takeschars > MAXCOLS-dcol+1) {
      dline++;
      dcol=0;
      if(dline >= NUMDUPLINES) return;
      gotoscr(DUPLINE+dline,0);
    }

    /* Output the string.					     */

    for(ich=0; ich<dsize; ich++) {
      mputc(*(++lptr));
    }
    dcol += dsize;

    /* Output "=size ". 					     */

    sprintf(outbuf,"=%d :",dfreq);
    for(ich=0; outbuf[ich]!=':'; ich++) {
      mputc(outbuf[ich]);
      dcol++;
    }
  }
}

mclear()
{
  scr_clear();
}
meol()
{
  scr_eol();
}

gotoscr(iline,icol)
int iline,icol;
{
  scr_curs(iline,icol);
}

mgetch()
{
  return(scr_getc());
}

mputc(ch)
char ch;
{
  scr_putc((int)ch);
}
}
