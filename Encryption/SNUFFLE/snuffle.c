#include <stdio.h>
#include "snefru.h"

#define NMAX 10000

main(argc,argv)
int argc;
char *argv[];
{
 register int ch;
 static unsigned char x[NMAX];
 register unsigned char y = 0;
 static unsigned char h[NMAX];
 static unsigned char m[32];
 static unsigned char l[64];
 static unsigned char k[64];
 register int n = 64;
 register int i;
 register WORD32 *wm = &m[0];
 register WORD32 *wl = &l[0];
 register int level = 3;

 SetupHash512();

 for (i = 0;i < 64;i++)
   x[i] = k[i] = h[i] = 0;
   /* What matters is x[9...63], y, k[0...63], h[0...63]. */

 i = 0;
 while (((ch = getchar()) != EOF) && (ch != '\n'))
   if (i < 64)
     k[i++] = (unsigned char) ch;
   else if (i < 119)
     x[i++ - 55] = (unsigned char) ch;
 if (argv[1])
   for (i = 0;argv[1][i] && (i < 64);i++)
     h[i] = argv[1][i];

 while ((ch = getchar()) != EOF)
  {
   if (!(n & 31))
    {
     for (i = 0;i < 64;i++)
       l[i] = k[i] ^ h[n - 64 + i];
     Hash512(wm,wl,level,8);
    }

   x[n] = x[n - 24] + x[n - 55] + ((unsigned char) ch);
   h[n] = x[n] + m[n & 31];
   y += h[n];
   (void) putchar((char) y);

   n++;
   if (n == NMAX)
    {
     for (i = 0;i < 64;i++)
      {
       x[(n & 31) + i] = x[n - 64 + i];
       h[(n & 31) + i] = h[n - 64 + i];
      }
     n = (NMAX & 31) + 64;
    }
  }
}
