/*--- nd2main.c --  Main program for NEWDES2 encryption.
 *
 *  See NEWDES2.C
 *
 *  This program is probably not of great interest to anyone.
 *  It's pretty fast, though.
 *
 *  Written by Mark Riordan  August 1990.
 *  This code is hereby placed in the public domain.
 */
#include <stdio.h>
#include <fcntl.h>
#ifdef MSDOS
#include <io.h>
#endif
#include <errno.h>
#include <stdlib.h>

char author[] = "Mark Riordan  1100 Parker  Lansing MI  48912   Aug 1990";

#include "newdespr.h"
#include "uucodepr.h"

#ifdef __STDC__
#define P(s) s
#else
#define P(s) ()
#endif

void procoutbuf P((void));
void usage P((void));

int getopt P((int     argc,char    **argv, char *opts));

#define TRUE 1
#define FALSE 0

#define BUFSIZE 24576
static unsigned char buf[BUFSIZE];
unsigned char *bufptr;
unsigned int bytesinbuf;
int docip = FALSE;
int inhandle, outhandle;

#define PREFERRED_UUENCODE_LEN  45


main(argc,argv)
int argc;
char *argv[];
{
#define LINEBUFSIZE  80
#define KEYSIZE 15
   static unsigned char linebuf[LINEBUFSIZE];

   extern unsigned char *optarg;
   char c, *cptr;
   enum {cipnone, cipencipher, cipdecipher} cipflag = cipnone;
   size_t charsread;
   unsigned char key[KEYSIZE], *incptr, *outcptr;
   unsigned int charscip;
   int uuflag = FALSE, gotcip = FALSE;
   int encipher;
   int j;
   unsigned int bytesinline;


   while((c = getopt(argc,argv,"cdeuk:")) != -1) {
      switch (c) {
         case 'd':
            encipher = FALSE;
            gotcip = TRUE;
            break;
         case 'e':
            encipher = TRUE;
            gotcip = TRUE;
            break;
         case 'c':
            docip = TRUE;
            break;
         case 'k':
            incptr = optarg;
            outcptr = key;
            for(j=0; j<KEYSIZE; j++) {
               if(!(*incptr)) incptr = optarg;
               *(outcptr++) = *(incptr++);
            }
            break;
         case 'u':
            uuflag = TRUE;
            break;

      }
   }

   /* Clear the parameters so that users typing "ps" or "w" can't
    * see the password.
    */

   for(j=1; j<argc; j++) {
      cptr = argv[j];
      while(*cptr) *(cptr++) = '\0';
   }

   inhandle = fileno(stdin);
   outhandle = fileno(stdout);

#ifdef MSDOS
   /* Output file is binary unless we are uuencoding.
    */
   if(!(uuflag && encipher)) {
      setmode(outhandle,O_BINARY);
   }

   /* Input is binary unless we are uudecoding.
    */
   if(!(uuflag && !encipher)) {
      setmode(inhandle,O_BINARY);
   }
#endif

   if(!gotcip) {
      usage();
      exit(1);
   }

   /* If we are using the cipher, prepare the key. */

   if(docip) {
      if(encipher) {
         newdes_set_key_encipher(key);
      } else {
         newdes_set_key_decipher(key);
      }
   }

   /* If we must uudecode, read the input a line at a time. */

   if(uuflag && !encipher) {
      /* Must uudecode input */
      bufptr = buf;
      bytesinbuf = 0;

      while(fgets(linebuf,LINEBUFSIZE,stdin)) {
         bytesinline = uudecode(linebuf,bufptr);
         bufptr += bytesinline;
         bytesinbuf += bytesinline;
         if(bytesinbuf > BUFSIZE-80) procoutbuf();
      }
      procoutbuf();

   } else {
      /* We are reading a binary file.  */

      while((charsread=read(inhandle,buf,BUFSIZE)) > 0) {
         if(docip) {
            charscip = newdes_buf(buf,charsread);
         } else {
            charscip = charsread;
         }

         if(!uuflag) {
            write(outhandle,buf,charscip);
         } else {
            bufptr = buf;
            while(charscip) {
               bytesinline = charscip >= PREFERRED_UUENCODE_LEN ?
                 PREFERRED_UUENCODE_LEN : charscip;
               uuencode(bufptr,bytesinline,linebuf);
               puts(linebuf);
               charscip -= bytesinline;
               bufptr += bytesinline;
            }
         }
      }
   }
}

/*--- function procoutbuf --------------------------------------------
 *
 *   Process bytes we have read in and uudecoded.
 *   This means possibly deciphering them, and certainly writing
 *   some of the bytes out.  Since deciphering can be done only
 *   on 8-byte chunks, if the number of bytes in the buffer
 *   isn't a multiple of 8, move the spare bytes from the end
 *   to the beginning, to be processed next time.
 *
 *    Entry    buf contains the buffer.
 *             bytesinbuf  is the number of bytes in the buffer.
 *             docip       is TRUE if we should decipher.
 *             bufptr      points to the next free spot in the buffer.
 *
 *    Exit     (Probably) some of the bytes have been written out,
 *               optionally first being deciphered.
 *             buf         may contain some bytes shifted down from the end.
 *             bytesinbuf  has been adjusted.
 *             bufptr      has been adjusted.
 */
void
procoutbuf()
{
   unsigned int procbytes, mybytes;
	unsigned char *mybufptr, *noncipptr;

   if(docip) {
		procbytes = (bytesinbuf/8) * 8;
      newdes_buf(buf,procbytes);
   } else {
      procbytes = bytesinbuf;
   }
   write(outhandle,buf,procbytes);

   bytesinbuf -= procbytes;
	noncipptr = buf+procbytes;
   for(mybufptr=buf, mybytes=bytesinbuf; mybytes--;) {
		*(mybufptr++) = *(noncipptr++);
   }
   bufptr = mybufptr;
}

void
usage()
{
   fputs("Enciphers/deciphers input using 64-bit block cipher\n",stderr);
   fputs("  similar to DES, with optional uuencode.\n",stderr);
   fputs("Usage: newdes2 {-d|-e} [-c] [-u] -k key <in >out\n",stderr);
   fputs("  -d  means decipher and/or uudecode\n",stderr);
   fputs("  -e  means encipher and/or uuencode\n",stderr);
   fputs("  -c  means apply the encryption pass (else plaintext\n",stderr);
   fputs("      is copied or uuencoded/uudecoded).\n",stderr);
   fputs("  -u  means uuencode (for -e) or uudecode (for -d)\n",stderr);
}
