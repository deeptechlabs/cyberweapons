/*-- desxmain.c -- Program to perform encryption/decryption
 *  using RSA Data Security's DESX algorithm.
 *
 *  Implements ECB mode only (simple block-by-block independent
 *  encryption).  The output file is 1-8 bytes longer than input
 *  on encryption, and vice versa on decryption.
 *  This is because the last byte of the last block is reserved
 *  for storing the number of real data bytes in the last block.
 *  This idea is taken from SunOS's DES implementation.
 *
 *  Note that much of the code in this main program deals with
 *  handling the last block.
 *
 *  Mark Riordan  March 1994, based on my desmain of 5 March 1991
 */

#include <stdio.h>
#ifdef MSDOS
#include <io.h>
#define read _read
#define write _write
#endif
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#ifdef MACTC
#include <console.h>
#include <unix.h>
#endif

#include "usagepro.h"
#include "getoptpr.h"
#include "desx.h"

static char *Author =
 "Mark Riordan  1100 Parker  Lansing, MI  48912  mrr@ripem.msu.edu";
static char Author_email[] = 
  {'M','R','R',':',' ','m','r','r','@',
   'r','i','p','e','m','.','m','s','u','.','e','d','u','\0'};
static char *date_written= " 7 March 1991 and 25 Feb 94";
static char *Author2= "DES code by Richard Outerbridge";
static char Author2_email[] = 
  {'R','W','O',':',' ','7','1','7','5','5','.','2','0','4','@',
    'C','o','m','p','u','S','e','r','v','e','.','c','o','m','\0'};
static char *author3= "DESX name trademarked by RSA Data Security, Inc.";

short int Encipher;
int Debug = 0;

static char *usage_msg[] = {
   "desx--Implements RSA Data Security's DESX cipher, as used in",
   "  BSAFE and MailSafe.  DESX is simply DES with an XOR before",
   "  and after each block encryption.  It has a 120-bit keyspace,",
   "  as compared with DES'x 56-bit keyspace.  Algorithm by RSA Data Security;",
   "  code by Richard Outerbridge and Mark Riordan.",
   "Usage:  desx {-e|-d} {-k key|-h hexkey} [-p] [-b] [-D] <in >out",
   "  where:",
   "  -e     means encipher; -d means enciper. ",
   "  key    is a 16-character ASCII key.  If '-p' is not given,",
   "         each of the first 8 characters will have its LOW bit",
   "         adjusted to yield an odd-parity byte, giving a total",
   "         of 56 bits of effective key.  In either case the next",
   "         eight characters are used as-is for the Whitening key.",
   "  hexkey is a 32 digit hex key, which will be modified as above.",
   "  -p     disables the forcing of odd-parity on the DES key.",
   "  -b     selects Electronic Code Book (EBC) mode, which is",
   "         basic independent block-by-block encryption. ",
   "         Default is Cipher Block Chaining (CBC) mode, in which",
   "         each plaintext block is XORed with the ciphertext output",
   "         of the previous block before being encrypted.  For CBC,",
   "         an initialization vector (IV) of 0's is used.",
   "  -D     turns on debug mode.",
   " ",
   " The last byte of the last block of an encrypted file contains",
   " the number of good bytes in that block (can be zero).",
   " DESX is a trademark of RSA Data Security, Inc. but the algorithm",
	" itself is freely usable by anybody.",
   NULL
};

typedef unsigned long int UINT32;

int
main(argc,argv)
int argc;
char *argv[];
{
#define MAXKEY 200
#define TRUE 1
#define FALSE 0

#define DEBUG 1

#ifdef DEBUGBUF
#define BUFSIZE1 16
#define BUFSIZE2 16
#else
#define BUFSIZE1 4096 
#define BUFSIZE2 4096
#endif
   unsigned char key[MAXKEY];
   char line[3];
   unsigned char *keyarg;
   int inhand, outhand;
   FILE *instream=stdin,*outstream=stdout;
   unsigned char *buf, *blockptr, *begbptr, *endbptr, *buf1, *buf2;

   extern unsigned char *optarg;
   char c;
   int gotcip = FALSE, gotkey=FALSE, hexkey=FALSE, oddpar=TRUE;
   int  j, parity, bit, ich, keylen, bytesinbuf, extra=0;
   int bufgood=0, buf2bytes, deschars;
   enum enum_desmodes {ECB, CBC} blockmode = CBC;
   UINT32 iv[2] = {0, 0};
   UINT32 ivnext[2];

   struct DESXContext desx_ctx;
   struct DESXKey desx_key;
#ifdef MACTC
   argc = ccommand(&argv);
#endif
   /* Crack the command line. */

   while((c = getopt(argc,argv,"dek:h:Dpb")) != -1) {
      switch (c) {
         case 'd':
            Encipher = FALSE;
            gotcip = TRUE;
            break;
         case 'e':
            Encipher = TRUE;
            gotcip = TRUE;
            break;
         case 'k':
            keyarg = optarg;
            gotkey = TRUE;
            break;
         case 'h':
            keyarg = optarg;
            gotkey = TRUE;
            hexkey = TRUE;
            break;
         case 'D':
            Debug = TRUE;
            break;
         case 'p':
            oddpar = FALSE;
            break;
         case 'b':
            blockmode = ECB;
            break;
      }
   }

   if(!(gotkey && gotcip)) {
      usage(NULL,usage_msg);
      exit(1);
   }

   /* Zero-fill the DES key (with odd parity)
    */
   for(j=0; j<8; j++) key[j] = 0x01;

   /* Zero-fill the DESX key (with real zeros)
    */
   for(; j<16; j++) key[j] = 0x00;

   /* Process the key.  For both hex and ASCII keys, zero-pad
    * the DES key if the one provided is less than 8 bytes.
    */
   keylen = strlen((char *)keyarg);
   if( keylen > MAXKEY ) keylen = MAXKEY;
   
   if( hexkey ) {
      /* Process a hex key.  Only adjust parity if forced to.
       */
      if( keylen&1 ) {
         fputs("Hex key must have even number of hex digits.\n",stderr);
         return 1;
      }
      keylen /= 2;
      line[2] = '\0';
      for( j = 0; j < keylen; j++ ) {
         line[0] = keyarg[2*j];
         line[1] = keyarg[2*j+1];
         sscanf(line,"%2x",&ich);
         if( j > 7 || (oddpar == FALSE) ) {
            key[j] = ich;
         } else {
           c = ich;
           for( parity = 0x01, bit = 1; bit < 8; bit++ ) {
               c >>= 1; 
               parity ^= (c&0x01);
           }
           key[j] = (ich&0xfe) | parity;
         }
      }
       
   } else {
      /* Process an ASCII key.  Set parity as requested.
       */
      deschars = keylen > 8 ? 8 : keylen;
      for( j = 0; j < deschars; j++ ) {
         if( oddpar == TRUE ) {
            c = keyarg[j];
            for( parity = 0x01, bit = 1; bit < 8; bit++ ) {
               c >>= 1;
               parity ^= (c&0x01);
            }
            key[j] = (keyarg[j]&0xfe) | parity;
         } else {
            key[j] = keyarg[j];
         }
      }
          
      /* Copy the DESX key characters, if any */
      for(; j<keylen; j++) key[j] = keyarg[j];
   }

   for(j=0; j<8; j++) {
      desx_key.DESKey64[j] = key[j];
      desx_key.Whitening64[j] = key[j+8];
   }
#ifdef DEBUG
   if(Debug) {
      fprintf(stderr,"DES       Key in hex=");
      for(j=0; j<8; j++) fprintf(stderr,"%-2.2x",desx_key.DESKey64[j]);
      putc('\n',stderr);
      fprintf(stderr,"Whitening Key in hex=");
      for(j=0; j<8; j++) fprintf(stderr,"%-2.2x",desx_key.Whitening64[j]);
      putc('\n',stderr);
      fflush(stderr);
   }
#endif

#ifdef OUTER
   deskey(key,1-Encipher); 
#else
   DESXKeySetup(&desx_ctx,&desx_key);
#endif
   
#ifdef DEBUG
   if(Debug) {
      fprintf(stderr," preWhitening in hex=");
      for(j=0; j<2; j++) fprintf(stderr,"%08lx ",desx_ctx.PreWhitening64[j]);
      putc('\n',stderr);
      fprintf(stderr,"postWhitening in hex=");
      for(j=0; j<2; j++) fprintf(stderr,"%08lx ",desx_ctx.PostWhitening64[j]);
      putc('\n',stderr);
      fflush(stderr);
   }
#endif

   inhand = fileno(instream);
   outhand = fileno(outstream);

#ifdef MSDOS
   setmode(inhand,O_BINARY);
   setmode(outhand,O_BINARY);
#endif

   /* Do the encipherment/decipherment.
    * This code may be difficult to follow, because I go out of my
    * way to do I/O in large chunks that are nice round numbers
    * so as to make use of the operating system's I/O facilities
    * as efficiently as possible.
    *
    * Note that I also try to allow for input that comes in chunks
    * of non-multiples of 8 bytes (as might happen when reading from
    * a socket over the net, for instance).
    *
    * "extra" is the number of bytes in the buffer mod 8 (i.e.,
    * those that won't be processed on this pass).
    */
   if(Encipher) {
      buf = malloc(BUFSIZE1+8);

      while((bytesinbuf=read(inhand,(char *)buf+extra,BUFSIZE1)) > 0) {
         bytesinbuf += extra;
         blockptr = begbptr = buf;
         extra = 7&bytesinbuf;
         endbptr = blockptr - extra + bytesinbuf;
         for(; blockptr != endbptr; blockptr += 8) {
#ifdef OUTER
            des(blockptr,blockptr);
#else
            if(blockmode == CBC) {
               /* In Cipher Block Chaining mode, first XOR the input
                * with the output from the last block.
                */
               *((UINT32 *)blockptr)     ^= iv[0];
               *((UINT32 *)(blockptr+4)) ^= iv[1];
            }
            DESXEncryptBlock(&desx_ctx,blockptr,blockptr);
            /* Save the encrypted output of this block for next
             * time.  Needed in CBC mode only, but an explicit
             * test for CBC here would probably only slow things down.
             */
            iv[0] = *((UINT32 *) blockptr);
            iv[1] = *((UINT32 *) (blockptr+4));
#endif
         }
         write(outhand,(char *)begbptr,bytesinbuf-extra);
         /* If the number of bytes wasn't a multiple of 8,
          * copy the extra bytes back to the beginning of the buffer
          * and next time, start the read just after these bytes.
          * This will be no more than 7 bytes.
          */
         if(extra) {
            for(j=0; j<extra; j++) buf[j] = blockptr[j];
         }
      }
      buf[7] = extra;

      if(blockmode == CBC) {
         *((UINT32 *)buf)     ^= iv[0];
         *((UINT32 *)(buf+4)) ^= iv[1];
      }
#ifdef OUTER
      des(buf,buf);
#else
      DESXEncryptBlock(&desx_ctx,buf,buf);
#endif
      write(outhand,(char *)buf,8);
   } else {
      /* Decipher the input.
       * This is more complicated than above, because we have to
       * detect when we have the last block of the file and
       * special-case it.
       * In order to do this efficiently, I use double-buffering.
       * buf1 is the buffer currently being processed.
       * buf2 is the "dirty" buffer that is waiting to be flushed.
       * We don't flush buf2 as soon as it's decrypted because
       * it may have the last block, which needs to be treated
       * differently.
       *
       * The below code may answer the question:  "Should I try
       * to write programs while watching a James Bond movie?"
       */
      buf1 = malloc(BUFSIZE2);
      buf2 = malloc(BUFSIZE2);
      if(!buf1 || !buf2) {
         fputs("Cannot allocate memory!",stderr);
         exit(1);
      }

      while((bytesinbuf=read(inhand,(char *)buf1+extra,BUFSIZE2)) > 0) {
         bytesinbuf += extra;
         blockptr = begbptr = buf1;
         extra = 7&bytesinbuf;
         endbptr = blockptr - extra + bytesinbuf;
         for(; blockptr != endbptr; blockptr += 8) {
            ivnext[0] = *((UINT32 *)blockptr);
            ivnext[1] = *((UINT32 *)(blockptr+4));
#ifdef OUTER
            des(blockptr,blockptr);
#else
            DESXDecryptBlock(&desx_ctx,blockptr,blockptr);
#endif
            if(blockmode == CBC) {
               /* In Cipher Block Chaining mode, XOR the result
                * with the output from the last block.
                */
               *((UINT32 *)blockptr)     ^= iv[0];
               *((UINT32 *)(blockptr+4)) ^= iv[1];
               iv[0] = ivnext[0];
               iv[1] = ivnext[1];
            }
#ifdef DEBUG2
				if(Debug) {
					int j;
					for(j=0; j<7; j++) fprintf(stderr,"%2.2x ",blockptr[j]);
					fprintf(stderr,"\n");
				}
#endif
         }
         if(bufgood) {
            /* This isn't the first buffer, so we can flush it. */
            write(outhand,(char *)buf2,buf2bytes);
         }
         if(extra) {
            for(j=0; j<extra; j++) buf2[j] = blockptr[j];
         }
         buf = buf1; buf1 = buf2; buf2 = buf;
         buf2bytes = bytesinbuf-extra;
         bufgood = 1;
      }
      /* OK--this buffer contains the last block.
       */
      buf2bytes = buf2bytes - 8 + buf2[buf2bytes-1];
      write(outhand,(char *)buf2,buf2bytes);
   }
   return 0;
}
}
