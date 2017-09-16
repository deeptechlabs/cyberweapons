/*
 * Maintenance tests for the Data Encryption Standard
 *
 * From National Bureau of Standards Special Publication 500-61
 *
 * Written by David Barrett (barrett%asgard@boulder.Colorado.EDU)
 *
 * Exit status 0 for success, non-zero for failure
 */
#include <stdio.h>
#include <string.h>
#include "des.h"

extern int optind;
extern char *optarg;

int verbose = 0;
char *progName;

#define BLOCKSIZE	8
#define TESTCOUNT	4

typedef char  block[BLOCKSIZE];

block testRes[TESTCOUNT] = {
   { 0xbf, 0x1f, 0xf3, 0x7b, 0xc4, 0x6c, 0xc2, 0xca },
   { 0x1d, 0xfc, 0xf1, 0xc8, 0x44, 0xe8, 0x4a, 0x9b },
   { 0x00, 0xb8, 0x2c, 0xbb, 0xe5, 0x8d, 0xbb, 0x9f },
   { 0x24, 0x6e, 0x9d, 0xb9, 0xc5, 0x50, 0x38, 0x1a }
};

int testCounts[TESTCOUNT] = { 3, 6, 8, 64 };

char *testMessages[TESTCOUNT] = {
   "  Test 1: Output Stuck Fault Test\n",
   "  Test 2: Test 1 plus Sbox, P and E Test\n",
   "  Test 3: Test 2 plus Complete Stuck Fault Test\n",
   "  Test 4: Test 3 plus IP and IP inverse -- Tests Everything\n",
};

void showBlock(stream, src)
   FILE *stream;
   char *src;
{
   register unsigned size = BLOCKSIZE;
   do {
      fprintf(stream, "%.2x", (unsigned char) *src++);
   } while (--size != 0);
}

int main(argc, argv)
   int argc;
   char *argv[];
{
   int	    ch, exitcode = 0, count;
   char	    *chp;
   keyType  key;
   int	    res, testnum;
   block    plain, keybits;

   progName = *argv;
   if ((chp = strrchr(progName, '/')) != (char *) 0) progName = chp+1;

   while ((ch = getopt(argc, argv, "v")) != EOF) switch (ch) {
   case 'v':
      verbose++;
      break;
   case '?':
   default:
usage:
      fprintf(stderr, "usage: %s [-v ]\n", progName);
      return 1;
   }
   argc -= optind;
   argv += optind;

   if (argc != 0) goto usage;

   key = (keyType) 0;
   desMakeKey(&key, keybits, BLOCKSIZE, 0);
   if (key == (keyType) 0) {
      fprintf(stderr, "%s: couldn't allocate memory for encryption key\n",
	 progName);
      return 1;	 
   }

   for (testnum = 0; testnum < TESTCOUNT; testnum++) {
      count = testCounts[testnum];
      if (verbose) {
	 fputs(testMessages[testnum], stderr);
      }
      memset(keybits, 0x55, BLOCKSIZE);
      memset(plain,   0xff, BLOCKSIZE);
      do {
	 desMakeKey(&key, keybits, BLOCKSIZE, 0);	/* 0 means encrypt */
	 des(plain, plain, key);
	 des(keybits, plain, key);
	 desMakeKey(&key, keybits, BLOCKSIZE, 1);	/* 1 means decrypt */
	 des(keybits, plain, key);
      } while (--count != 0);
      res = memcmp(keybits, testRes[testnum], BLOCKSIZE);
      if (res != 0) {
	 fprintf(stderr, "%s: test %d failed, expected ", progName, testnum+1);
	 showBlock(stderr, testRes[testnum]);
	 fputs(" got ", stderr);
	 showBlock(stderr, keybits);
	 putc('\n', stderr);
	 exitcode |= (1 << testnum);
      }
   }

   if (verbose) {
      if (exitcode) {
	 fprintf(stderr, "%s: Test Failed\n", progName);
      } else {
	 fprintf(stderr, "%s: Test Passed\n", progName);
      }
   }

   free(key);
   return exitcode;
}
