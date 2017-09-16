/* Copyright (c) 1993 Colin Plumb.  This code may be freely
   distributed under the terms of the GNU General Public Licence. */
 
   /* This was developed using Borland C for the IBM PC */
 
#include "idea.h"
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
 
#define RAND16 (rand() ^ rand() << 1)
 
uchar far bigbuf1[65528];
uchar far bigbuf2[65528];
 
void
timetest(uchar iv[8], uint16 *key)
{
        clock_t t1, t2;
        uchar iv2[8];
        int i;
 
	for (i = 0; i < 8; i++)
		iv2[i] = iv[1];
 
        printf("Starting time test.\n");
 
        t1 = clock();
        for (i = 0; i < 32; i++) {
                IdeaCFB(iv, key, bigbuf1, bigbuf2, 8192);
                IdeaCFBx(iv2, key, bigbuf2, bigbuf2, 8192);
        }
        t2 = clock();

        printf("%4x / %4x  %4x / %4x  %4x / %4x  %4x / %4x\n",
                iv[0], iv2[0], iv[1], iv2[1], iv[2], iv2[2], iv[3], iv2[3]);
        t2 -= t1;
	t1 = t2*1000/CLK_TCK;
        printf("Time taken for 64 64K buffers (4096 K): %lu clocks, %u.%03u seconds\n",
                t2, (unsigned)(t2/1000), (unsigned)(t2 % 1000));
}
 
int
main(int argc, char **argv)
{
        ulong j;
        uint16 a, b, c, d, i;
        uint16 key[KEYSIZE];
	uchar in[8], out1[8], out2[8], out3[8];
        uchar buf1[16], buf2[16], buf3[16];
 
        if (argc < 2)
                srand((unsigned)time(0));
        else {
                argv++;        /* suppress silly warning */
                srand(argc);
        }
 
        printf("Starting to test...\n");
	for (j = 0; j < 10000; j++) {
		if (j % 100 == 0)
			printf("%5lu\r", j);
	 
		for (i = 0; i < 8; i++)
			in[i] = rand();
		for (i = 0; i < KEYSIZE; i++)
			key[i] = RAND16;
		Idea(in, out1, key);
		for (i = 0; i < 8; i++)
			out3[i] = out2[i] = in[i];
		IdeaCFB(out2, key, buf1, buf1, 1); /* buf1 args are dummies */
		IdeaCFBx(out3, key, buf1, buf1, 1);
		for (i = 0; i < 4; i++)
			if (out1[i] != out2[i] || out2[i] != out3[i])
				break;
		if (i < 4) {
			printf("Unequal for j = %lu\n", j);
			for (i = 0; i < 8; i++)
				printf("%2x - %2x / %2x / %2x    %4x\n",
				       in[i], out1[i], out2[i], out3[i], key[i]);
		}
		for (i = 0; i < 16; i++)
			buf1[i] = rand();
		IdeaCFB(out2, key, buf1, buf2, 3);
		IdeaCFBx(out3, key, buf2, buf3, 3);
		a = 0;
		for (i = 0; i < 8; i++)
			if (out2[i] != out3[i])
				a = 1;
		for (i = 0; i < 16; i++)
			if (buf1[i] != buf3[i])
				a = 1;
		if (a) {
			printf("CFB problem for j = %lu\n", j);
			for (i = 0; i < 8; i++)
				printf("%2x / %2x = %2x     %4x\n",
				     out1[i], out2[i], out3[i], key[i]);
			for (i = 0; i < 8; i++)
				printf("%2x -> %2x -> %2x   %4x\n",
				     buf1[i], buf2[i], buf3[i], key[i+8]);
			for (i = 8; i < 16; i++)
				printf("%2x -> %2x -> %2x\n",
				     buf1[i], buf2[i], buf3[i]);
		}
	} /* for (j) */
        timetest(in, key);
        return 0;
}
