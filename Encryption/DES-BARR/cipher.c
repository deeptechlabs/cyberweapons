/*
 * cipher - a more secure replacement for UNIX crypt program 
 *
 * Generic block encipherment/decipherment program 
 * modified specifically for the Data Encryption Standard using
 * Cipher Block Feedback (CFB) mode as described in FIPS pub 81.
 *
 * See also FIPS PUB 74.
 *
 * Permission is given copy and use this program provided it is not sold
 * for profit.
 *
 * Written by David A. Barrett (barrett%asgard@boulder.Colorado.EDU)
 */
#include <stdio.h>
#include <string.h>
#include "cipher.h"

extern int errno;
extern char *sys_errlist[];
extern int sys_nerr;

extern int optind;
extern char *optarg;

#ifdef __STDC__
extern int getkey(char *, char *, unsigned);
#else
extern int getkey();
#endif

#ifdef MSDOS
#define PATHCHAR '\\'
#else
#define PATHCHAR '/'
#endif

static char ident[] = 
" @(#) cipher.c  version 2.01 26-Feb-91 by Dave Barrett\n";
static char rcsIdent[] = 
" @(#) cipher.c  $Revision: 1.5 $ $Date: 91/01/23 12:11:11\n";

#define	IO_BUFSIZE	1024		/* small for data cache speed */
#define MAXCIPHER	10		/* maximum multiple encipherments */
#define KEYBUFLEN	129		/* allow long keys */

typedef struct {
   char	   iv[DES_BLOCKSIZE];
   keyType key;
   int	   ivlen;
   int	   decr;
} KeyItem;

KeyItem keys[MAXCIPHER];
char    bufs[2][IO_BUFSIZE];
char    *progName;

typedef char block[DES_BLOCKSIZE];

/*
 * Keys which could accidently reproduce the plaintext with multiple-encryption
 */
block badKeys[16] = {
   { 0xe0, 0x00, 0xe0, 0x00, 0xf0, 0x00, 0xf0, 0x00 },
   { 0x00, 0xe0, 0x00, 0xe0, 0x00, 0xf0, 0x00, 0xf0 }, 
   { 0xfe, 0x1e, 0xfe, 0x1e, 0xfe, 0x0e, 0xfe, 0x0e },
   { 0x1e, 0xfe, 0x1e, 0xfe, 0x0e, 0xfe, 0x0e, 0xfe }, 
   { 0xe0, 0x1e, 0xe0, 0x1e, 0xf0, 0x0e, 0xf0, 0x0e },
   { 0x1e, 0xe0, 0x1e, 0xe0, 0x0e, 0xf0, 0x0e, 0xf0 }, 
   { 0x00, 0xfe, 0x00, 0xfe, 0x00, 0xfe, 0x00, 0xfe },
   { 0xfe, 0x00, 0xfe, 0x00, 0xfe, 0x00, 0xfe, 0x00 },
   { 0x00, 0x1e, 0x00, 0x1e, 0x00, 0x0e, 0x00, 0x0e },
   { 0x1e, 0x00, 0x1e, 0x00, 0x0e, 0x00, 0x0e, 0x00 }, 
   { 0xe0, 0xfe, 0xe0, 0xfe, 0xf0, 0xfe, 0xf0, 0xfe },
   { 0xfe, 0xe0, 0xfe, 0xe0, 0xfe, 0xf0, 0xfe, 0xf0 }, 
   { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },	/* self-dual */
   { 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe },	/* self-dual */
   { 0xe0, 0xe0, 0xe0, 0xe0, 0xf0, 0xf0, 0xf0, 0xf0 },	/* self-dual */
   { 0x1e, 0x1e, 0x1e, 0x1e, 0x0e, 0x0e, 0x0e, 0x0e },	/* self-dual */
};

/*
 * Return nonzero if the key is one of the well-known "weak" keys (FIPS Pub 74)
 */
int weakKey(keybits)
   char *keybits;
{
   register block *keyp = &badKeys[0];		/* common compiler bug here */
   register unsigned count = sizeof(badKeys) / sizeof(badKeys[0]);
   register unsigned i;

   do {
      for (i = 0; i < DES_BLOCKSIZE; i++) {
	 if ((((*keyp)[i] ^ keybits[i]) & 0xfe) != 0) goto notfound;
      }
      break;
notfound:
      keyp++;
   } while (--count != 0);
   return count;
}

int hexdigit(ch)
   register char ch;
{
   if (ch >= '0' && ch <= '9') return ch - '0';
   if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
   if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
   return -1;
}

/*
 * Convert an ASCII hexadecimal number to it's corresponding string of bytes
 */
unsigned hex(d, s, size)
   register char *d, *s;
   register unsigned size;
{
   register unsigned count = 0;
   register int lo, hi;

   if (size > 0) do {
      hi = hexdigit(*s++);
      if (hi < 0) break;
      lo = hexdigit(*s++);
      if (lo < 0) break;
      *d++ = (hi << 4) | lo;
      count++;
   } while (count < size);
   return count;
}

/*
 * Because we are using CFB, we always encrypt.  Since we'd like to be
 * able to run the chips in either mode, perhaps CBC would be better.
 * If CBC is used though, the last block must be handled in OFB mode.  Sigh.
 *
 * Returns:  
 *  -1 - out of memory (program exits, and error reported)
 *   0 - success
 *   1 - key is a weak key
 */
int setKey(kp, keybits, keystr, mode)
   register keyType *kp;
   char *keybits, *keystr;
   int  mode;
{
   register int res;

   if (keystr != (char *) 0) {
      desKey(keybits, keystr, ' ');		/* space padded */
      memset(keystr, '\0', strlen(keystr));	/* blank out key asap */
   }

   res = weakKey(keybits);

   makeKey(kp, keybits, DES_BLOCKSIZE, mode);	/* 0 means encrypt mode */
   memset(keybits, '\0', DES_BLOCKSIZE);	/* zero out bits asap */

   if (*kp == (keyType) 0) {
      fprintf(stderr, "%s: couldn't allocate memory for encryption key\n",
	 progName);
      exit(1);
   }
   return res;
}

int main(argc, argv)
   int argc;
   char *argv[];
{
   int 	    i, ch, rcount, wcount; 
   int	    ivcount = 0, keycount = 0, decrcount = 0, ciphercount = 1;
   int      checkkey = 1, keystrlen = 0, keylen = 0;
   char	    *chp, *ibuf = bufs[1], *obuf = bufs[0];
   char     keybits[DES_BLOCKSIZE], ivbits[DES_BLOCKSIZE];
   char	    keybuf[KEYBUFLEN], chkbuf[KEYBUFLEN], ivbuf[DES_BLOCKSIZE];
   KeyItem  *kip;

   progName = *argv;
   if ((chp = strrchr(progName, PATHCHAR)) != (char *) 0) progName = chp+1;

   if (strcmp(progName, "decipher")==0 || strcmp(progName, "decrypt")==0)  {
      keys[decrcount].decr = 1;
   } else {
      keys[decrcount].decr = 0;
   }

   while ((ch = getopt(argc, argv, "devni:k:x:")) != EOF) switch (ch) {
   case 'd':  
      if (decrcount == MAXCIPHER) goto cipherError;
      keys[decrcount++].decr = 1;		/* decrypt */
      break;
   case 'e':  
      if (decrcount == MAXCIPHER) goto cipherError;
      keys[decrcount++].decr = 0;		/* encrypt */
      break;
   case 'i':					/* initialization vector */
      if (ivcount == MAXCIPHER) goto cipherError;
      memset(ivbits,  '\0', DES_BLOCKSIZE);		/* pad iv  with '\0' */
						/* default IV is zero */
      i  = hex(ivbuf, optarg, DES_BLOCKSIZE);	/* right-justified */
      memcpy(ivbits + DES_BLOCKSIZE - i, ivbuf, i);
      memcpy(keys[ivcount++].iv, ivbits, DES_BLOCKSIZE);
      break;
   case 'x':					/* key in hexadecimal */
      if (keycount == MAXCIPHER) goto cipherError;
      memset(keybits, '\0', DES_BLOCKSIZE);		/* pad key with '\0' */
      keylen = hex(keybits, optarg,DES_BLOCKSIZE);	/* left-justified */
      i = setKey(&keys[keycount++].key, keybits, (char *) 0, 0);
      goto chkKey;
   case 'k':  					/* key as a string */
      if (keycount == MAXCIPHER) goto cipherError;
      i = setKey(&keys[keycount++].key, keybits, optarg, 0);
chkKey:
      if (i) {
	 fprintf(stderr, "%s: warning -- weak key selected\n", progName);
      }
      break;
   case 'v':
      checkkey++;
      break;
   case 'n':
      --checkkey;
      break;
   case '?':
   default:
usage:
      fprintf(stderr, 
"usage: %s [ -v|n ] {-de} {-i hex_initvec } {-x hex_key } {-k keystring }\n", 
      progName);
      return 1;
cipherError:
      fprintf(stderr, 
      "%s: can't exceed %d multiple-encipherments\n", progName, MAXCIPHER);
      return 1;
   }
   argc -= optind;
   argv += optind;

   if (argc != 0) goto usage;
   if (decrcount == 0) decrcount++;

   if (decrcount > ciphercount) ciphercount = decrcount;
   if (ivcount   > ciphercount) ciphercount = ivcount;
   if (keycount  > ciphercount) ciphercount = keycount;

   while (decrcount < ciphercount) keys[decrcount++].decr = keys[0].decr;
   while (ivcount < ciphercount) {			/* default IV = 0 */
      keys[ivcount].ivlen = DES_BLOCKSIZE;
      memset(keys[ivcount++].iv, '\0', DES_BLOCKSIZE);
   }

   while (keycount < ciphercount) {		   /* must input all keys */
      keystrlen = getkey("Input Key:", keybuf, KEYBUFLEN-1);
keyRetry:
      if (keystrlen <= 0) {
	 fprintf(stderr, "%s: couldn't get key\n", progName);
	 return 1;
      }
      if (checkkey) {
	 i = getkey("Verify Key:", chkbuf, KEYBUFLEN-1);
	 if (i != keystrlen || memcmp(chkbuf, keybuf, i) != 0) {
	    keystrlen = getkey("Keys didn't match; try again\r\nInput Key:", 
	       keybuf, KEYBUFLEN-1);
	    goto keyRetry;
	 }
	 memset(chkbuf, '\0', i);
      }
      keybuf[keystrlen] = '\0';
      i = setKey(&keys[keycount].key, keybits, keybuf, 0);
      if (i) {
	 keystrlen = 
	    getkey("Weak key generated; use another one\r\nInput Key:",
	       keybuf, KEYBUFLEN-1);
	 goto keyRetry;
      }
      keycount++;
   }

   do {
      rcount = read(0, obuf, IO_BUFSIZE);
      if (rcount <= 0) break;

      i = ciphercount;
      kip = keys;
      do {
	 chp = obuf; obuf = ibuf; ibuf = chp;
	 kip->ivlen = desCFB(
	    obuf, ibuf, rcount, kip->iv, kip->ivlen, kip->key, kip->decr);
	 kip++;
      } while (--i != 0);

      wcount = write(1, obuf, rcount);
   } while (wcount == rcount);

   if (rcount < 0) {
      fprintf(stderr, "%s: read failed: %s\n", progName, sys_errlist[errno]);
      return 3;
   }
   if (rcount != 0 && rcount != wcount)  {
      fprintf(stderr, "%s: write failed: %s\n", progName, sys_errlist[errno]);
      return 2;
   }

   return 0;
}
