/*--- tprencod.c -- Program to test prencode and prdecode,
 *  routines to do RFC 1113 binary/ASCII encoding/decoding
 *  similar to uuencode.
 *  This program is similar to uuencode and uudecode.
 *
 *  Mark Riordan   21 Feb 1991
 *  This code is hereby placed in the public domain.
 */

#include <stdio.h>
#include <stdlib.h>
#include "../main/prcodepr.h"

#ifdef MSDOS
#include <fcntl.h>
#include <io.h>
#include <errno.h>
#endif

static char *author = "Mark Riordan  1100 Parker  Lansing, MI  48912";

static char *usage_msg[] = {
   "Usage:  tprencode {-e|-d} <in >out",
   "  where:",
   "  -e  means encode binary input to RFC 1113 printable format",
   "      (similar to but distinct from uuencode format).",
   "  -d  means decode printable to binary",
   NULL
};

int
main(argc,argv)
int argc;
char *argv[];
{

#define BUFSIZE  24576
#define CHUNKSIZE 48
#define LINESIZE  256
   int encode=-1, argerror = 0;
   int inhandle, outhandle;
   int bytesinbuf, nbytes, ch;
   unsigned char *bytebuf, *bufptr, *source, *target;
   char line[LINESIZE], *cptr;
   FILE *instream;

   while(EOF != (ch = getopt(argc,argv,"de"))) {
      switch(ch) {
         case 'e':
            encode = 1;
            break;

         case 'd':
            encode = 0;
            break;

         default:
            argerror = 1;
      }
   }

   if(argerror || encode<0) {
      usage(NULL,usage_msg);
      exit(1);
   }

   bytebuf = (unsigned char *) malloc(BUFSIZE+CHUNKSIZE);

   if(encode) {
      inhandle = fileno(stdin);
#ifdef MSDOS
      /* Input is binary.
       */
      setmode(inhandle,O_BINARY);
#endif

      while(bytesinbuf = read(inhandle,bytebuf,BUFSIZE)) {
         bufptr = bytebuf;
         while(bytesinbuf > 0) {
            nbytes = bytesinbuf<CHUNKSIZE ? bytesinbuf : CHUNKSIZE;
            prencode(bufptr,nbytes,line);
            puts(line);
            bufptr += nbytes;
            bytesinbuf -= nbytes;
         }
      }

   } else {
      outhandle = fileno(stdout);
#ifdef MSDOS
      /* Output file is binary.
       */
      setmode(outhandle,O_BINARY);
#endif
      instream = stdin;
      bufptr = bytebuf;
      bytesinbuf = 0;
      /* Read in a line at a time and decode it into a big buffer.
       */
      while(fgets(line,LINESIZE,instream)) {
			cptr = line;
			while(*cptr==' ') cptr++;
         nbytes = prdecode(cptr,bufptr,CHUNKSIZE);
         bytesinbuf += nbytes;
         bufptr += nbytes;

         /* If the binary output buffer filled, flush it.
          * For efficiency for the operating system, flush
          * only a nice big round number of bytes.
          */
         if(bytesinbuf >= BUFSIZE) {
            write(outhandle,bytebuf,BUFSIZE);
            bytesinbuf -= BUFSIZE;

            /* This shouldn't happen, but if there are some bytes
             * left at the end of the buffer, copy them to the
             * beginning of the buffer.
             */
            if(bytesinbuf) {
               for(target=bytebuf, source=bytebuf+BUFSIZE;
                 bytesinbuf--; ) {
                  *(target++) = *(source++);
               }
            }
            bufptr = bytebuf + bytesinbuf;
         }
      }
      if(bytesinbuf) write(outhandle,bytebuf,bytesinbuf);
   }


}
