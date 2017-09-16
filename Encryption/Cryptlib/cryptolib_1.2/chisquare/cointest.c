/*
 *	Test for variation from simple biased-coin behavior
 */
#include "bash.h"

#include <stdio.h>

static long count[2];

int
getbit(stream)
FILE *stream;
{
	static shift = 7, byte;
	int bit;

	if (shift == 7) {
		byte = getc(stream);
		if (byte == EOF)
			return EOF;
		shift = -1;
	}
	shift++;
	bit = (byte >> shift) & 1;
	count[bit]++;
	return bit;
}

putbit(stream, bit)
FILE *stream;
int bit;
{
	static shift = -1, byte = 0;

	shift++;
	byte |= bit << shift;
	if (shift == 7) {
		putc(byte, stream);
		byte = 0;
		shift = -1;
	}
}

int
unbias(src, dst)
char *src, *dst;
{
	FILE *fin, *fout;
	int bit1, bit2;
	long n;

	n = 0;
	(void) creat(dst, 0666);
	fin = fopen(src, "r");
	fout = fopen(dst, "w");
	for (;;) {
		do {
			if ((bit1 = getbit(fin)) == EOF)
				goto out;
			if ((bit2 = getbit(fin)) == EOF)
				goto out;
		} while (bit1 == bit2);
		putbit(fout, bit1);
		n++;
	}
out:	fclose(fin);
	fclose(fout);
	return n;
}

main(argc, argv)
int argc;
char *argv[];
{
	int i;
	double n, x2;
	char *src, *dst;
	extern double chi();

	src = argv[1];
	dst = "B";
	do {
		count[0] = count[1] = 0;
		unbias(src, dst);
		n = count[0] + count[1];
		x2 = 0.0;
		for (i = 0; i < 2; i++)
			x2 = x2 + (count[i] - 0.5*n)*(count[i] - 0.5*n)/(0.5*n);
		printf("%10d bits   chi = %f\n", count[0] + count[1], chi(x2, 1));
		src = "B";
		dst = "A";
		count[0] = count[1] = 0;
		unbias("B", "A");
		n = count[0] + count[1];
		x2 = 0.0;
		for (i = 0; i < 2; i++)
			x2 = x2 + (count[i] - 0.5*n)*(count[i] - 0.5*n)/(0.5*n);
		printf("%10d bits   chi = %f\n", count[0] + count[1], chi(x2, 1));
		src = "A";
		dst = "B";
	} while (count[0] + count[1]);
}
