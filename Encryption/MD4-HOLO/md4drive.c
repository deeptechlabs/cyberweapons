/*
*--------------------------------------------------------------------------*
* (C) Copyright 1990, RSA Data Security, Inc.  All rights reserved.        *
* License to copy and use this software is granted provided it is          *
* identified as the "RSA Data Security, Inc. MD4 message digest algorithm" *
* in all material mentioning or referencing this software or function.     *
*                                                                          *
* License is also granted to make and use derivative works provided such   *
* works are identified as "derived from the RSA Data Securitry, Inc. MD4   *
* message digest algorithm" in all material mentioning or referencing the  *
* derived work.                                                            *
*                                                                          *
* RSA Data Security, Inc. makes no representations concerning the          *
* merchantability of this software or the suitability of the software      *
* for any particular purpose.  It is provided "as is" without express      *
* or implied warranty of any kind.                                         *
*                                                                          *
* These notices must be retained in any copies of any part of this         *
* documentation and/or software.                                           *
*--------------------------------------------------------------------------*
** ********************************************************************
** md4driver.c -- sample routines to test                            **
** MD4 message digest algorithm.                                     **
** Updated: 2/16/90 by Ronald L. Rivest                              **
** (C) 1990 RSA Data Security, Inc.                                  **
** ********************************************************************
*/

#include <stdio.h>
#ifdef MSDOS
#include <string.h>
#include <time.h>
#endif
#include "md4.h"

/* MDtimetrial()
** A time trial routine, to measure the speed of MD4.
** Measures speed for 1M blocks = 64M bytes.
*/
MDtimetrial()
{ WORD X[16];
  MDstruct MD;
  unsigned int i;
#ifdef MSDOS
  long t;
#else
  double t;
#endif
  for (i=0;i<16;i++) X[i] = 0x01234567 + i;
#ifdef MSDOS
  printf("MD4 time trial. Processing 50'000 64-character blocks...\n");
  t = time(NULL);
#else
  printf
  ("MD4 time trial. Processing 1 million 64-character blocks...\n");
  clock();
#endif
  MDbegin(&MD);
#ifdef MSDOS
  for (i=0;i<50000;i++) MDupdate(&MD,X,512);
#else
  for (i=0;i<1000000;i++) MDupdate(&MD,X,512);
#endif
  MDupdate(&MD,X,0);
#ifdef MSDOS
  t = time(NULL) - t; /* in seconds */
  MDprint(&MD); printf(" is digest of 3.2M byte test input.\n");
  printf("Seconds to process test input:   %ld\n",t);
  printf("Characters processed per second: %ld.\n",3200000/t);
#else
  t = (double) clock(); /* in microseconds */
  MDprint(&MD); printf(" is digest of 64M byte test input.\n");
  printf("Seconds to process test input:   %g\n",t/1e6);
  printf("Characters processed per second: %ld.\n",(int)(64e12/t));
#endif
}

/* MDstring(s)
** Computes the message digest for string s.
** Prints out message digest, a space, the string (in quotes) and a
** carriage return.
*/
MDstring(s)
unsigned char *s;
{ unsigned int i, len = strlen(s);
  MDstruct MD;
  MDbegin(&MD);
  for (i=0;i+64<=len;i=i+64) MDupdate(&MD,s+i,512);
  MDupdate(&MD,s+i,(len-i)*8);
  MDprint(&MD);
  printf(" \"%s\"\n",s);
}

/* MDfile(filename)
** Computes the message digest for a specified file.
** Prints out message digest, a space, the file name, and a
** carriage return.
*/
MDfile(filename)
char *filename;
{ FILE *f = fopen(filename,"rb");
  unsigned char X[64];
  MDstruct MD;
  int b;
  if (f == NULL)
     { printf("%s can't be opened.\n",filename); return; }
  MDbegin(&MD);
  while ((b=fread(X,1,64,f))!=0) MDupdate(&MD,X,b*8);
  MDupdate(&MD,X,0);
  MDprint(&MD);
  printf(" %s\n",filename);
  fclose(f);
}

/* MDfilter()
** Writes the message digest of the data from stdin onto stdout,
** followed by a carriage return.
*/
MDfilter()
{ unsigned char X[64];
  MDstruct MD;
  int b;
  MDbegin(&MD);
  while ((b=fread(X,1,64,stdin))!=0) MDupdate(&MD,X,b*8);
  MDupdate(&MD,X,0);
  MDprint(&MD);
  printf("\n");
}

/* MDtestsuite()
** Run a standard suite of test data.
*/
MDtestsuite()
{
  printf("MD4 test suite results:\n");
  MDstring("");
  MDstring("a");
  MDstring("abc");
  MDstring("message digest");
  MDstring("abcdefghijklmnopqrstuvwxyz");
  MDstring
  ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
  MDfile("abcfile"); /* Contents of file abcfile are "abc" */
}

void help()
{
  printf("Usage: md4 [filename] [-sstring] [-t] [-x] [-h]\n\n");
  printf("For each command line argument in turn:\n");
  printf(" filename   -- prints message digest and name of file\n");
  printf(" -sstring   -- prints message digest and contents of string\n");
#ifdef MSDOS
  printf(" -t         -- prints time trial statistics for 3.2M bytes\n");
#else
  printf(" -t         -- prints time trial statistics for 64M bytes\n");
#endif
  printf(" -x         -- execute a standard suite of test data\n");
  printf(" -h         -- prints this help\n");
  printf(" (no args)  -- writes messages digest of stdin onto stdout\n");
  printf("                (if stdin is not a tty)\n");
}

main(argc,argv)
int argc;
char *argv[];
{ int i;
  /* For each command line argument in turn:
  ** filename          -- prints message digest and name of file
  ** -sstring          -- prints message digest and contents of string
  ** -t                -- prints time trial statistics for 64M bytes
  ** -x                -- execute a standard suite of test data
  ** (no args)         -- writes messages digest of stdin onto stdout
  */
  if (argc==1){
    if (isatty(0)){
      printf("Usage: md4 [filename] [-sstring] [-t] [-x] [-h]\n");
      exit(0);
    }
    MDfilter();
  }
  else
    for (i=1;i<argc;i++)
      if (argv[i][0]=='-' && argv[i][1]=='s') MDstring(argv[i]+2);
      else if (strcmp(argv[i],"-t")==0)       MDtimetrial();
      else if (strcmp(argv[i],"-x")==0)       MDtestsuite();
      else if (strcmp(argv[i],"-h")==0)       help();
      else                                    MDfile(argv[i]);
}

/*
** end of md4driver.c
*/
