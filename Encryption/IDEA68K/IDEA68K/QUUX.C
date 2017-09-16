#include <stdio.h>

typedef unsigned short uint16;
uint16 rand();
void InvertIdeaKey(const uint16 key1[52], uint16 key2[52]);
void InvertIdeaKey2(const uint16 key1[52], uint16 key2[52]);

void
printshort(uint16 s)
{
	uint16 i = 16;
	while (i--)
		putchar(s & (1<<i) ? '1' : '0');
}

void
printshort4(uint16 x[4], uint16 y[4], uint16 z[4])
{
	putchar(' ');
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

	putchar('<');
	putchar(' ');
	printshort(y[0]);
	putchar(' ');
	printshort(y[1]);
	putchar(' ');
	printshort(y[2]);
	putchar(' ');
	printshort(y[3]);
	putchar(' ');
	putchar('>');
	putchar('\n');

	putchar(' ');
	putchar('\\');
	printshort(z[0]);
	putchar(' ');
	printshort(z[1]);
	putchar(' ');
	printshort(z[2]);
	putchar(' ');
	printshort(z[3]);
	putchar('/');
	putchar('\n');
}

void
printshorts(uint16 *x, uint16 *y, uint16 *z, uint16 size)
{
	uint16 i;
	i = 0;
	while (i < size) {
		printshort4(x+i, y+i, z+i);
		i += 4;
	}
	return;
}

int
main(void)
{
	uint16 key[52], key1[52], key2[52];
	uint16 i, j, k, t;
	i = 0;
	for (i = 0; i < 1000; i++) {
		for (j = 0; j < 52; j++)
			key[j] = (rand()<<1) ^ rand();
		InvertIdeaKey(key, key1);
		InvertIdeaKey2(key, key2);
		if (memcmp(key1, key2, sizeof(key1))) {
			printf("Different for i = %d!\n", i);
			for (k = 0; k < 52/2; k++) {
				t= key[k];
				key[k] = key[51-k];
				key[51-k] = t;
			}
			puts("Keys:");
			printshorts(key, key1, key2, 52);
			getchar();
		}
	}
	puts("All tested.");
	return 0;
}
