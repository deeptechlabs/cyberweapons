From msuinfo!agate!howland.reston.ans.net!usc!sdd.hp.com!hplabs!unix.sri.com!csl.sri.com!boucher Tue Nov 16 21:41:12 1993
Path: msuinfo!agate!howland.reston.ans.net!usc!sdd.hp.com!hplabs!unix.sri.com!csl.sri.com!boucher
From: boucher@csl.sri.com (Peter K. Boucher)
Newsgroups: comp.ai.genetic,sci.crypt
Subject: Re: Strong random number generators?
Date: 12 Nov 1993 00:44:12 GMT
Organization: Computer Science Lab, SRI International
Lines: 192
Distribution: world
Message-ID: <2bum8sINN98j@roche.csl.sri.com>
References: <1993Nov5.183248.29604@cs.tcd.ie> <2bfl7tINN3ne@redwood.csl.sri.com> <16C83F0BF.RAHNJ@vm1.ulaval.ca>
NNTP-Posting-Host: redwood.csl.sri.com
Xref: msuinfo comp.ai.genetic:1721 sci.crypt:21045

If this shows up twice (shouldn't -- I cancelled the other one),
sorry, ignore the other one.

RAHNJ@vm1.ulaval.ca (Joel Rahn) writes:
|> OK, I didn't compile the code and I only scanned it rapidly so maybe this
|> is right out-to-lunch, but doesn't the above text describe a test of
|> simple uniformity and a 'runs up' (or 'runs down') test with run-length
|> equal to two? An LCG that is even worth considering passes these two
|> tests easily, no?

New, and improved anal.c, uses chi-square.

Does the 'runs up' (or 'runs down') test with run-length equal to two
get me anything over the standard chi-square test?  I left it in.

BTW, the  buf[i] = (((seed = (1103515245*seed +12345)) >> 16) & 0xff);
test fails this one at high numbers.  It's too evenly distributed.

-Peter

/* ***************************************************************
 * anal.c --
 *
 * Copyright 1993 Peter K. Boucher
 * Permission to use, copy, modify, and distribute this
 * software and its documentation for any purpose and without
 * fee is hereby granted, provided that the above copyright
 * notice appear in all copies.
 *
 * Usage:  anal [input_file [output_file]]
 *
 * This program counts the occurances of each character in a file
 * and notifies the user when a the distribution is too ragged or
 * too even.
 *
 * Because the chance of getting byte B after byte A should be 1:256
 * (for all A's and B's), the program also checks that the successors
 * to each byte are randomly distributed.  This means that for each byte
 * value (0 - 255) that occurs in the text, a count is kept of the
 * byte value that followed in the text, and the frequency distribution
 * of these succeeding bytes is also checked.
 *
 */

#include <stdio.h>

#define BYTESIZE 256
#define BUFSIZE 8192
#ifdef DEBUG
#define PASSED_OFNAME "/tmp/analocc.pss"
#define PASSED_SFNAME "/tmp/analsuc.pss"
#define FAILED_OFNAME "/tmp/analocc.fld"
#define FAILED_SFNAME "/tmp/analsuc.fld"
#endif

#define	Vmin	(205.33) /*  1% chance it's less */
#define Vlo	(239.39) /* 25% chance it's less */
#define Vhi	(269.88) /* 75% chance it's less */
#define Vmax	(310.57) /* 99% chance it's less */

#define min_nps 5

#define SHOW_RESULT(F,t,s) \
     fprintf(F, "%s n =%10ld, V=%.2lf\n", \
		 t,    s,       V);

unsigned long cnt[BYTESIZE] = {0}; /* should be all zeros. */
unsigned long succeed[BYTESIZE][BYTESIZE] = {{0}}; /* should be all zeros. */

static unsigned char buf[BUFSIZE];
static FILE *ifp, *ofp;

FILE *
my_fopen(file, type)
char *file, *type;
{
  FILE *fp;

  if ((fp = fopen(file, type)) == NULL) {
      (void)fprintf(stderr, "Can't open '%s' for '%s'\n", file, type);
      exit(1);
  }
  return(fp);
}

double
get_V(N,Y)
unsigned long N;
unsigned long *Y;
{
#define k (BYTESIZE)
#define p (1.0/k)
    double sum = 0.0;
    double n = N;
    int i;

    for (i=0; i<k; i++) {
	sum += ((Y[i]*Y[i])/p)/n;
    }
    return( sum - n );
}

unsigned long
fill_arrays()
{
   unsigned long size=0L;
   int ch,next,l,i;

   if ((ch = getc(ifp)) != EOF) { /* prime the pump */
       cnt[ch] = size = 1L;
       while ((l = fread(buf, 1, BUFSIZE, ifp)) > 0) {
	   for (i=0; i<l; i++) {
	       size++;
	       next = buf[i];
	       cnt[next]++;
	       succeed[ch][next]++;
	       ch = next;
	   }
       }
   }
   fclose(ifp);
   return( size );
}

void
anal_ize_text()
{
   int   	  i;
   double         V;
   unsigned long  size;

   if ((size = fill_arrays()) < (BYTESIZE*min_nps)) {
       fprintf(stderr, "File too small (%ld) to meaningfully analyze\n",
	       size);
       exit(0);
   }

   V = get_V(size,cnt);
   SHOW_RESULT(ofp, "Occurances: ", size);
   if ((V < Vmin) || (V > Vmax)) {
#ifdef DEBUG
       FILE *failed=my_fopen(FAILED_OFNAME, "a");
       SHOW_RESULT(failed, "", size);
       fclose(failed);
#endif
       fprintf(stderr, "Character occurances non-random\n");
   } else if ((V > Vlo) && (V < Vhi)) {
#ifdef DEBUG
       FILE *excell=my_fopen(PASSED_OFNAME, "a");
       SHOW_RESULT(excell, "", size);
       fclose(excell);
#endif
       fprintf(ofp,
"================ Frequency distribution excellent! ====================\n");
   }

   if (size >= (BYTESIZE*BYTESIZE*min_nps)) {
       for (i=0,V=0.0; i<BYTESIZE; i++) {
	   V += get_V(cnt[i],succeed[i]);
       }
       V /= BYTESIZE;
       SHOW_RESULT(ofp, "Successions:", size>>8);
       if ((V < Vmin) || (V > Vmax)) {
#ifdef DEBUG
	   FILE *failed=my_fopen(FAILED_SFNAME, "a");
	   SHOW_RESULT(failed, "", size>>8);
	   fclose(failed);
#endif
	   fprintf(stderr, "Character successions non-random\n");
       } else if ((V > Vlo) && (V < Vhi)) {
#ifdef DEBUG
	   FILE *excell=my_fopen(PASSED_SFNAME, "a");
	   SHOW_RESULT(excell, "", size>>8);
	   fclose(excell);
#endif
	   fprintf(ofp,
"================= Successor randomness excellent! =====================\n");
       }
   }
}  

int
main (int argc, char* argv[])
{
   ifp = (argc > 1) ? my_fopen(argv[1],"r") : stdin;
   ofp = (argc > 2) ? my_fopen(argv[2],"w") : stdout;
   anal_ize_text();

   return(0);
}




