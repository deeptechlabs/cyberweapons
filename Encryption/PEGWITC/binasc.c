/* binasc.c
**
**  BAS64 armour by Mr. Tines <tines@windsong.demon.co.uk>
*/
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>

#include "binasc.h"

#define LINE_LEN   48L /* binary bytes per armour line */
#define MAX_LINE_SIZE 66 /* expands to this plus \n\0 over*/

static char err_decode_failed[] =
"Pegwit; Out of range characters encountered in ASCII armouring.\n"
"Terminating.\n";

/* Index this array by a 6 bit value to get the character corresponding
 * to that value.  */
 static unsigned char bintoasc[] 
   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Index this array by a 7 bit value to get the 6-bit binary field
 * corresponding to that value.  Any illegal characters return high bit set.
 */
static
unsigned char asctobin[] = {
   0200,0200,0200,0200,0200,0200,0200,0200,
   0200,0200,0200,0200,0200,0200,0200,0200,
   0200,0200,0200,0200,0200,0200,0200,0200,
   0200,0200,0200,0200,0200,0200,0200,0200,
   0200,0200,0200,0200,0200,0200,0200,0200,
   0200,0200,0200,0076,0200,0200,0200,0077,
   0064,0065,0066,0067,0070,0071,0072,0073,
   0074,0075,0200,0200,0200,0200,0200,0200,
   0200,0000,0001,0002,0003,0004,0005,0006,
   0007,0010,0011,0012,0013,0014,0015,0016,
   0017,0020,0021,0022,0023,0024,0025,0026,
   0027,0030,0031,0200,0200,0200,0200,0200,
   0200,0032,0033,0034,0035,0036,0037,0040,
   0041,0042,0043,0044,0045,0046,0047,0050,
   0051,0052,0053,0054,0055,0056,0057,0060,
   0061,0062,0063,0200,0200,0200,0200,0200
};


#define PAD      '='
/* the armoured value corresponding to no bits set */
#define ZERO   'A'

static char asciiBuffer[MAX_LINE_SIZE];
static char *writeHead=asciiBuffer;
static int space = MAX_LINE_SIZE-2;
static unsigned char bin[3];
static int inBin = 0;

void burnBinasc(void)
{
  memset( asciiBuffer, 0, sizeof(asciiBuffer) );
  memset( bin, 0, sizeof(bin) );
}

static int flushBuffer(FILE * stream)
{

   if(asciiBuffer == writeHead )return 1;

   writeHead[0] = '\n';
   writeHead[1] = '\0';

   writeHead=asciiBuffer;
   space = MAX_LINE_SIZE - 2;

   return fputs(asciiBuffer, stream) >= 0;
}


/* output one group of up to 3 bytes, pointed at by p, on file f. */
static void encode(unsigned char p[3], char buffer[4], int count)
{
   if(count < 3)
   {
      p[count] = 0; /* some bits from this byte may be used */
      buffer[2] = buffer[3] = PAD;
   }
   buffer[0] =     bintoasc[p[0] >> 2];
   buffer[1] =     bintoasc[((p[0] << 4) & 0x30) | ((p[1] >> 4) & 0x0F)];
   if(count > 1)
   {
      buffer[2] = bintoasc[((p[1] << 2) & 0x3C) | ((p[2] >> 6) & 0x03)];
      if(count > 2) buffer[3] = bintoasc[p[2] & 0x3F];
   }
}

static int push3bytes(FILE *stream)
{
   /* is there space left on the buffer ?*/
   if(space < 4)
   {
      int push = flushBuffer(stream);
      if(!push) return 0;
   }
   encode(bin, writeHead, inBin);
   inBin = 0;
   writeHead+=4;
   space -= 4;
   return 1;
}


/* flush any left-overs */
int flushArmour(FILE * stream)
{
   int result = 1;
   if(inBin) result = push3bytes(stream);
   if(result) result = flushBuffer(stream);
   return result;
}

size_t fwritePlus(const void *ptr, size_t size, size_t n, FILE *stream)
{
   size_t result = 0;
   int bytesOver = 0;
   unsigned char *out = (unsigned char *)ptr;
/*
fprintf(stderr, "fwrite Plus writing %d bytes\n", n*size);
{
   int i;
   for(i=0; i<4; ++i)
   {
      fprintf(stderr,"%x %x %x %x\n",
      out[0], out[1], out[2], out[3]);
      out+=4;
   }
   out = (unsigned char*)ptr;
}
*/
   if(stdout != stream)
      return fwrite(ptr, size, n, stream);

   while(result < n)
   {
      bin[inBin] = *out;
      ++inBin;
      ++out;
      ++bytesOver;
      if(3 == inBin)
      {
         if(!push3bytes(stream)) return result;
         inBin=0;
      }
      if(bytesOver==size)
      {
         ++result;
         bytesOver = 0;
      }
   }
   return n;
}

int fputcPlus(int c, FILE *stream)
{
   if(stdout != stream)
      return fputc(c, stream);

   bin[inBin] = (unsigned char)(c & 0xFF);
   ++inBin;
   if(3 == inBin)
   {
      if(!push3bytes(stream)) return EOF;
      inBin=0;
   }
   return c;
}


/*-------------- Input ASCII Armoured Cyphertext ------------------------*/

static int decodeBuffer(char *inbuf, unsigned char *outbuf, int *outlength)
{
   unsigned char *bp;
   int   length;
   unsigned int c1,c2,c3,c4;
   int hit_padding = 0;

   length = 0;
   bp = (unsigned char *)inbuf;

/*fprintf(stderr, "decodeBuffer >%s<\n", inbuf);*/

   /* FOUR input characters go into each THREE output charcters */

   while(*bp != '\0' && !hit_padding)
   {
      /* check for padding */
      if(bp[3] == PAD)
      {
         hit_padding = 1; /* allow for quoted printable = -> =3D */
         if(bp[2] == PAD || !strcmp((char*)bp + 2, "=3D=3D"))
         {
            length += 1;
            bp[2] = ZERO;
         }
         else
            length += 2;
         bp[3] = ZERO;
      }
      else
         length += 3; /* unpadded */

      if(bp[0] & 0x80 || (c1 = asctobin[bp[0]]) & 0x80 ||
         bp[1] & 0x80 || (c2 = asctobin[bp[1]]) & 0x80 ||
         bp[2] & 0x80 || (c3 = asctobin[bp[2]]) & 0x80 ||
         bp[3] & 0x80 || (c4 = asctobin[bp[3]]) & 0x80)
      {
         fprintf(stderr, err_decode_failed);
         exit(1);
      }
      bp += 4;
      *outbuf++ = (unsigned char)((c1 << 2) | (c2 >> 4));
      *outbuf++ = (unsigned char)((c2 << 4) | (c3 >> 2));
      *outbuf++ = (unsigned char)((c3 << 6) | c4);
   }

   *outlength = length;
   return !hit_padding;

}

static unsigned char binaryBuffer[LINE_LEN];
static unsigned char *readHead = binaryBuffer;
static int bytesLeft = 0;
static int more = 1;

/* Acts like fread if the stream is a file; from stdin, however
** it expects that the data have been Base64 encoded, so we */

size_t freadPlus(void *ptr, size_t size, size_t n, FILE *stream)
{
   size_t result = 0;
   int bytesOver = 0;
   unsigned char *out = ptr;

   if(stdin != stream)
      return fread(ptr, size, n, stream);

   while(result < n)
   {
       /* start by satisying bytes from the buffer */
      if(bytesLeft >= size-bytesOver)
      {
         memcpy(out, readHead, size-bytesOver);
         bytesLeft -= (size-bytesOver);
         readHead += (size-bytesOver);
         out += (size-bytesOver);

         ++result;  /* a chunk satsified, so increment count */
         bytesOver = 0; /* and none left over */
      }
      else
      {
         memcpy(out, readHead, bytesLeft);
         bytesOver += bytesLeft;
         out += bytesLeft;
         bytesLeft = 0;
      }

      /* on buffer exhaustion */
      if(0==bytesLeft)
      {
         int l;
         char inBuf[MAX_LINE_SIZE];

         memset(binaryBuffer, 0, (size_t) LINE_LEN);

         if(!more) break; /* hit the termination */
         if(feof(stream)) break; /* end stop */

         inBuf[0] = 0; /* Added by George Barwood, 22/4/97 */
         fgets(inBuf, MAX_LINE_SIZE, stream);  /* 64+\n\0 */
         if('#' == inBuf[0]) break;

         l = strlen(inBuf);
         while(inBuf[l-1] < ' ' && l>0){--l; inBuf[l] = '\0';}

         more = decodeBuffer(inBuf, binaryBuffer, &bytesLeft);
         memset(inBuf, 0, MAX_LINE_SIZE);
         readHead = binaryBuffer;
      }
   }
/*
fprintf(stderr, "freadPlus returning %d bytes\n", result*size);
{
   int i;
   out = ptr;
   for(i=0; i<4; ++i)
   {
      fprintf(stderr,"%x %x %x %x\n",
      out[0], out[1], out[2], out[3]);
      out+=4;
   }
}
*/
   return result;
}
