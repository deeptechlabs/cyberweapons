#include <stdio.h>

typedef unsigned short uint16;
uint16 rand();
void ExpandUserKey(const uint16 userkey[8], uint16 key[52]);
void ExpandUserKey2(const uint16 userkey[8], uint16 key[52]);

void
printshort(uint16 s)
{
	uint16 i = 16;
	while (i--)
		putchar(s & (1<<i) ? '1' : '0');
}

void
printshort4(uint16 x[4], uint16 y[4])
{
	putchar('/');
	printshort(x[0]);
	putchar(' ');
	printshort(x[1]);
	putchar(' ');
	printshort(x[2]);
	putchar(' ');
	printshort(x[3]);
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
	putchar('/');
	putchar('\n');
}

void
printshorts(uint16 *x, uint16 *y, uint16 size)
{
	uint16 i;
	i = 0;
	while (i < size) {
		printshort4(x+i, y+i);
		i += 4;
	}
	return;
}

int
main(void)
{
	uint16 userkey[8], key1[52], key2[52];
	uint16 i, j;
	i = 0;
	for (i = 0; i < 1000; i++) {
		for (j = 0; j < 8; j++)
			userkey[j] = (rand()<<1) ^ rand();
		ExpandUserKey(userkey, key1);
		ExpandUserKey2(userkey, key2);
		if (memcmp(key1, key2, sizeof(key1))) {
			printf("Different for i = %d!\n", i);
			puts("Keys:");
			printshorts(key1, key2, 52);
			getchar();
		}
	}
	puts("All tested.");
	return 0;
}
