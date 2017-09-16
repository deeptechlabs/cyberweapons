#include <stdio.h>

typedef unsigned short uint16;
typedef unsigned char uchar;
uint16 rand();
void ExpandUserKey(const uint16 userkey[8], uint16 key[52]);
void ExpandUserKey2(const uint16 userkey[8], uint16 key[52]);
void Idea(const uchar dataIn[8], uchar dataOut[8], const uint16 key[52]);
void Idea2(const uchar dataIn[8], uchar dataOut[8], const uint16 key[52]);

void
printchar(uchar s)
{
	uint16 i = 8;
	while (i--)
		putchar(s & (1<<i) ? '1' : '0');
}

void
printchar8(uchar x[8], uchar y[8])
{
	putchar('/');
	printshort(x[0]);
	putchar(' ');
	printshort(x[1]);
	putchar(' ');
	printshort(x[2]);
	putchar(' ');
	printshort(x[3]);
	putchar(' ');
	printshort(x[4]);
	putchar(' ');
	printshort(x[5]);
	putchar(' ');
	printshort(x[6]);
	putchar(' ');
	printshort(x[7]);
	putchar('\\');
	putchar('\n');

	putchar('\\');
	printshort(y[0]);
	putchar(' ');
	printshort(y[1]);
	putchar(' ');
	printshort(y[2]);
	putchar(' ');
	printshort(y[3]);
	putchar(' ');
	printshort(y[4]);
	putchar(' ');
	printshort(y[5]);
	putchar(' ');
	printshort(y[6]);
	putchar(' ');
	printshort(y[7]);
	putchar('/');
	putchar('\n');
}

void
printbytes(uchar *x, uchar *y, uint16 size)
{
	uint16 i;
	i = 0;
	while (i < size) {
		printchar8(x+i, y+i);
		i += 8;
	}
	return;
}

int
main(void)
{
	uint16 userkey[8], key[52];
	uchar plain[8], cipher1[8], cipher2[8];
	uint16 i, j, k;

	srand(clock());
	i = 0;
	for (i = 0; i < 100; i++) {
		for (j = 0; j < 8; j++)
			userkey[j] = (rand()<<1) ^ rand();
		ExpandUserKey(userkey, key);
		for (j = 0; j < 100; j++) {
			for (k = 0; k < 8; k++)
				plain[k] = rand();
			Idea(plain, cipher1, key);
			Idea2(plain,cipher2, key);
			if (memcmp(cipher1, cipher2, sizeof(cipher1))) {
				printf("Different for i,j = %d,%d!\n", i, j);
				printbytes(cipher1, cipher2, 8);
				getchar();
			}
		}
		printf("i = %d\r", i);
		fflush(stdout);
	}
	puts("All tested.");
	return 0;
}
