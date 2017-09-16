/*
 * Data Encryption Standard Validation Tests
 *
 * From National Bureau of Standards Special Publication 500-20
 *
 * Written by David A. Barrett (barrett%asgard@boulder.Colorado.EDU)
 *
 * Exit status 0 for success, non-zero for failure
 */
#include <stdio.h>
#include <string.h>
#include "des.h"

extern int errno;
extern int optind;
extern char *optarg;

int verbose = 0;
char *progName;

#define LINELEN		80
#define BLOCKSIZE 	8

typedef char block[BLOCKSIZE];

int hexdigit(ch)
   register char ch;
{
   if (ch >= '0' && ch <= '9') return ch - '0';
   if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
   if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
   return -1;
}

void getItem(dst, src, size)
   register char *dst, *src;
   register unsigned size;
{
   register int ch;

   do {
      ch = hexdigit(*src++); ch = (ch << 4) | hexdigit(*src++);
      *dst++ = ch;
   } while (--size != 0);
}

/*
 * Returns:
 *    1 for decrypt, 0 for encrypt
 */
int getparms(src, key, plain, cipher)
   char *src, *key, *plain, *cipher;
{
   register int ch;
   int count = 0, decr = 0;

   while ((ch = *src) != '\n') {
      src++;
      switch (ch) {
      case 'K':
	 getItem(key, src, BLOCKSIZE);
	 src += 16;
	 count++;
	 break;
      case 'P':
	 getItem(plain, src, BLOCKSIZE);
	 src += 16;
	 count++;
	 break;
      case 'S':
	 getItem(cipher, src, BLOCKSIZE);
	 if (count == 1) {
	    decr = 1;
	 }
	 src += 16;
	 count++;
	 break;
      }
      if (count == 3) break;
   }
   return decr;
}

void showItem(stream, src, count)
   FILE *stream;
   char *src;
   int count;
{
   do {
      fprintf(stream, "%.2x", (unsigned char) *src++);
   } while (--count != 0);
}

int main(argc, argv)
   int argc;
   char *argv[];
{
   int	    ch, decr = 0, exitcode = 0;
   char	    *chp;
   int	    keylen;
   keyType  key;
   char	    line[LINELEN];
   block    cipher, plain, keystr, wbuf;
   int 	    lineno = 0;
   int	    res;

   progName = *argv;
   if ((chp = strrchr(progName, '/')) != (char *) 0) progName = chp+1;

   while ((ch = getopt(argc, argv, "v")) != EOF) switch (ch) {
   case 'v':
      verbose++;
      break;
   case '?':
   default:
usage:
      fprintf(stderr, "usage: %s [ -v ] < testdataFile\n", progName);
      return 1;
   }
   argc -= optind;
   argv += optind;

   if (argc != 0) goto usage;

   key = (keyType) 0;
   keylen = 8;
   do {
      lineno++;
      chp = fgets(line, LINELEN, stdin);
      if (chp == (char *) 0) break;

      decr = getparms(line, keystr, plain, cipher);

      if (*chp == '\n' || *chp == '#') continue;
      if (*chp == '"') {
	 if (verbose) {
	    fputs(&line[1], stdout);
	 }
	 continue;
      }

      desMakeKey(&key, keystr, keylen, decr);
      if (key == (keyType) 0) {
	 fprintf(stderr, "%s: couldn't allocate memory for encryption key\n",
	    progName);
	 return 1;	 
      }

      if (!decr) {
	 des(wbuf, plain, key);
	 res = memcmp(wbuf, cipher, 8);
      } else {
	 des(wbuf, cipher, key);
	 res = memcmp(wbuf, plain, 8);
      }
      if (res != 0) {
	 fprintf(stderr, "Failed--line %d:", lineno);
	 fputs(" k=", stderr);
	 showItem(stderr, keystr, 8);
	 fputs(" p=", stderr);
	 showItem(stderr, plain, 8);
	 fputs(" => ", stderr);
	 showItem(stderr, wbuf, 8);
	 fputs(" c=", stderr);
	 showItem(stderr, cipher, 8);
	 fputs("\n", stderr);
	 exitcode = 2;
      }
   } while (1);

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
