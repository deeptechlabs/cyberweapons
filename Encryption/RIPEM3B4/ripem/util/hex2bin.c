/*--- hex2bin.c -- Simple program to convert hex to binary.
 *
 *  Mark Riordan   8 May 92
 */

#include <stdio.h>
#include "hexbinpr.h"

#define BUFLEN 4000
unsigned char buf[BUFLEN], *bptr;

int
main(int argc, char *argv[])
{
#define LINELEN 400
   char line[LINELEN];
   int nbytes=0, ibytes;

   while(gets(line)) {
      ibytes = HexToBin(line,BUFLEN,buf+nbytes);
      nbytes += ibytes;
   }
   for(bptr=buf;nbytes--;) {
      putchar(*(bptr++));
   }
}
