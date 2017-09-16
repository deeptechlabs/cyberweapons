/*  PERIODIC.C -- Implement a periodic (polyalphabetic) cipher.
 *
 *  Called as:
 *
 *  periodic {-e|-d} -a alphafile -k keys
 *
 *  where:
 *
 *  -e	 specifies encipher;
 *  -d	 specifies decipher.
 *
 *  -a	 specifies a file name which contains the alphabet.
 *	 If this file contains the English alphabet in alphabetical
 *	 order, for instance, the resulting cipher will be a "Vigenere".
 *
 *  -k	 specifies a file name which contains the key in numeric form.
 *	 The number of numbers (in decimal form) in this key determines
 *	 the period.  Each number specifies the number of positions
 *	 the character must be shifted ahead (or back, for deciphering)
 *	 in the alphabet.
 *
 *
 *  Written by Mark Riordan    5 Sept 1988
 */

#define LINFILE 60
#define DEBUG 0
#define MAXALPHA 72
#define MAXKEY	72

#include "stdio.h"
#include "ctype.h"

extern int myindex();
extern FILE *fopen();
extern char *index();

char alpha[MAXALPHA];
int nalpha=0;
int key[MAXKEY];
int nkey=0;

main(argc,argv)
int argc;
char *argv[];
{
  char alphafile[LINFILE];
  char keyfile[LINFILE];
  FILE *alphastream, *keystream;
  int narg;
  int j;
  int ch;
  int gotargs=0;
  int gotenc=0, gotalpha=0, gotkey=0;
  int badarg = 0;
  int encip;
  int nkey=0;
  int result;
  int thiskey;
  int keyct=0;
  int chidx;
  char *thisarg;
  int keyidx=0;
  int newidx;

  for (narg=1; narg<argc; narg++) {
    if(strcmp(argv[narg],"-a")==0) {
      /* We have the alphabet file name in the next argument.		      */

      narg++;
      strcpy(alphafile,argv[narg]);
      gotalpha = 1;
    } else if(strcmp(argv[narg],"-k") == 0) {
      /* We have the key file name in the next argument.	     */
      narg++;
      strcpy(keyfile,argv[narg]);
      gotkey = 1;
    } else if(strcmp(argv[narg],"-e")==0) {
      /* Encipher flag. 					  */
      encip = 1;
      gotenc = 1;
    } else if(strcmp(argv[narg],"-d")==0) {
      /* Decipher flag. 					     */
      encip = 0;
      gotenc = 1;
    } else {
      badarg = 1;
    }
  } /* end for narg */

  if(badarg | !gotalpha | !gotkey | !gotenc) {
    fputs("periodic--Program to implement periodic (polyalphabetic) cipher.\n",stderr);
    fputs("Usage:  periodic {-e|-d}-a alphafile -k keyfile  \n",stderr);
    fputs("where:  -e means encipher, -d means decipher.\n",stderr);
    fputs("	   alphafile  is a file containing an alphabet; use 26 letters A-Z\n",stderr);
    fputs("		      if you want Vigenere.\n",stderr);
    fputs("	   keyfile    contains a series of decimal numbers that\n",stderr);
    fputs("		      comprise the key.\n",stderr);
  } else {
    /* Obtain the alphabet */

    alphastream = fopen(alphafile,"r");
    if(alphastream==NULL) {
      fputs("Cannot open alphabet file\n",stderr);
      exit(1);
    }
    while((ch=getc(alphastream)) != EOF) {
      if(isprint(ch)) {
	alpha[nalpha++] = ch;
      }
    }
    alpha[nalpha] = '\0';

    /* Get the keys */

    keystream = fopen(keyfile,"r");
    if(keystream==NULL) {
      fputs("Cannot open key file.\n",stderr);
      exit(1);
    }
    while((result = fscanf(keystream,"%d",&thiskey)) != EOF) {
      if(result <= 0) {
	exit(1);
      }
      if(!encip) thiskey = -thiskey;
      key[nkey++] = thiskey;
    }
#if DEBUG
    {  int j;
       char debch;

       fputs("alpha=",stderr);
       for(j=0; j<nalpha; j++) fputc(alpha[j],stderr);
       fputs("\nkeys=",stderr);
       for(j=0; j<nkey; j++) fprintf(stderr,"%d ",key[j]);
       putc('\n',stderr);
    }
#endif


    while((ch=getchar()) != EOF) {
      chidx = myindex(alpha,ch);
      if(chidx >= 0) {
	newidx = chidx + key[keyidx];
	if(newidx<0) {
	  newidx = newidx + nalpha;
	} else if(newidx >= nalpha) {
	  newidx = newidx - nalpha;
	}
	putchar(alpha[newidx]);
	if(++keyidx >= nkey) keyidx = 0;
      } else {
	putchar(ch);
      }
    }
  }
}

/*--- function myindex(string,ch)
 *
 */
int
myindex(string,ch)
char string[];
int ch;
{
  int idx;

  for(idx=0; string[idx]; idx++) {
    if(string[idx] == ch) return(idx);
  }
  return(-1);
}
}
