/*  Program to solve Caesarian simple-substitution ciphers
 *  by exhaustive search.
 *
 *  Written by Mark Riordan   1 July 1988
 */

#include "stdio.h"
#include "string.h"
#define ALFSIZE 26


char *allup  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
char *alllow = "abcdefghijklmnopqrstuvwxyz";

main(argc,argv)
int argc;
char *argv[];
{
  char *line;
  int nchars;
  int sft;
  int ich;
  int position;
  char *mychar;
  char *inalpha;
  char ch;
  int twoperline;

  line = argv[1];
  nchars = strlen(line);
  twoperline = nchars < 39;
  for(sft=0; sft<ALFSIZE-1; sft++) {
    for(ich=0,mychar=line; ich<nchars; ich++,mychar++) {
      ch = *mychar;
      if(inalpha = strchr(allup,ch)) {
	position = inalpha - allup + 1;
	if(position >= ALFSIZE) position = 0;
	ch = allup[position];
      } else if (inalpha= strchr(alllow,ch)) {
	position = inalpha -alllow + 1;
	if(position >= ALFSIZE) position = 0;
	ch = alllow[position];
      }
      *mychar = ch;
    }
    fputs(line,stdout);
    if(twoperline && sft%2 == 0) {
      fputs("  ",stdout);
    } else {
      putchar('\n');
    }
  }
 }
 }
