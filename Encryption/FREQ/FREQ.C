/* Counts the frequency of every character in a file.  */
/* By Peter Boucher, boucher@csl.sri.com */

#include <stdio.h>

FILE *my_fopen(file, type)
char *file, *type;
{
  FILE *fp;

  if (fp = fopen(file, type))
    return fp;
  (void) fprintf(stderr, "Can't open '%s' for '%s'\n", file, type);
  exit(1);
}


main(argc, argv)
int argc;
char **argv;
{
  register FILE *inf=((argc > 1) ? my_fopen(argv[1], "rb") : stdin);
  register FILE *outf=((argc > 2) ? my_fopen(argv[2], "w") : stdout);
  unsigned long cnt[256], sum=0, avg, lowthresh, highthresh, lowlim, highlim;
  register unsigned int i;

  for (i=0; i<256; i++) cnt[i] = 0L;

  while ((i=fgetc(inf)) != EOF)
  {
    ++cnt[i];
  }

  for (i=0; i<256; i++) sum += cnt[i];
  avg = sum/256;

  if (avg < 50L) 
  {
    lowthresh=avg/2L;
    highthresh = avg + (avg - lowthresh);
    lowlim = lowthresh/2L;
    highlim = highthresh*2L;
  } else if (avg < 200L)
  {
    lowthresh=(85L*avg)/100L;
    highthresh = avg + (avg - lowthresh);
    lowlim = (2L*lowthresh)/3L;
    highlim = (3L*highthresh)/2L;
  }  else if (avg < 1000L)
  {
    lowthresh=(92L*avg)/100L;
    highthresh = avg + (avg - lowthresh);
    lowlim = (3L*lowthresh)/4L;
    highlim = (4L*highthresh)/3L;
  } else if (avg < 10000L)
  {
    lowthresh=(965L*avg)/1000L;
    highthresh = avg + (avg - lowthresh);
    lowlim = (5L*lowthresh)/6L;
    highlim = (6L*highthresh)/5L;
  } else
  {
    lowthresh=(985L*avg)/1000L;
    highthresh = avg + (avg - lowthresh);
    lowlim = (9L*lowthresh)/10L;
    highlim = (10L*highthresh)/9L;
  }

  fprintf(outf, "average number of occurances/byte = %10ld.\n", avg);
  for (i=0; i<256; i++)
  {
    if ((cnt[i] < lowthresh) || (cnt[i] > highthresh)) {
      fprintf(outf, "%2.2x %10ld %s\n", i, cnt[i], (cnt[i] < lowthresh) ? "<" : ">");
      if ((cnt[i] < lowlim) || (cnt[i] > highlim))
      {
	fprintf(outf, "%2.2x %10ld GHAAK!\n", i, cnt[i]);
	exit(1);
      }
    }
  }
}
