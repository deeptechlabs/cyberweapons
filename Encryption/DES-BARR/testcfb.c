#include <stdio.h>
#include <string.h>
#include "des.h"

#define MAXBUFSIZE 	8192

int bufSize = 3;

char plain[MAXBUFSIZE], cipher[MAXBUFSIZE];

char ivbits[]  = { 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef };
char keybits[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };

char *progName;

extern int getopt();
extern int optind;
extern char *optarg;

int main(argc, argv)
   int argc;
   char *argv[];
{
   int exitCode = 0;
   char *chp;
   int ch, rcount, ivsize, wcount, decr = 0;
   keyType key = (keyType) 0;
   char iv[DES_BLOCKSIZE];

   progName = *argv;
   if ((chp = strrchr(progName, '/')) != (char *) 0) progName = chp+1;

   while ((ch = getopt(argc, argv, "ds:")) != EOF) switch (ch) {
   case 's':
      wcount = sscanf(optarg, "%d", &bufSize);
      if (wcount != 1) goto usage;
      break;
   case 'd':
      decr++;
      break;
   case '?':
   default:
usage:
      fprintf(stderr, "usage: %s [ -d ] [ -s bufsize ]\n", progName);
      return 1;
   }
   argc -= optind;
   argv += optind;

   if (argc != 0) goto usage;

   ivsize = DES_BLOCKSIZE;
   memcpy(iv, ivbits, ivsize);
   desMakeKey(&key, keybits, DES_BLOCKSIZE, 0);
   do {
      rcount = read(0, plain, bufSize);
      if (rcount <= 0) break;
      ivsize = desCFB(cipher, plain, rcount, iv, ivsize, key, decr);
      wcount = write(1, cipher, rcount);
   } while (1);

   return exitCode;
}
