#include <stdio.h>

typedef unsigned short uint16;
uint16 Mul(uint16, uint16), Mul2(uint16, uint16);

int
main(void)
{
	uint16 i, j;
	uint16 a, b;
	i = 0;
	do {
		printf("%d\r", i);
		fflush(stdout);
		j = 0;
		do {
			a = Mul(i, j);
			b = Mul2(i, j);
			if (a != b) {
				printf("%d * %d = %d and %d\n", i, j, a, b);
				printf("%d\r", i);
				fflush(stdout);
			}
		} while (++j != i);
	} while (++i);
	return 0;
}
