#include <stdio.h>

typedef unsigned short uint16;
uint16 MulInv(uint16);
uint16 MulInv2(uint16);
uint16 Mul2(uint16, uint16);

int
main(void)
{
	uint16 a2, a3, b2,b3;
	uint16 i = 0;
	do {
		if (!(i & 255))
			printf("i = %4x\n", i);
		a2 = MulInv(i);
		a3 = MulInv2(i);
		b2 = Mul2(a2,i);
		b3 = Mul2(a3,i);
		if (b2 != 1 || b3 != 1 || a2 != a3)
			printf("MulInv(%x) = %x (*= %x); MulInv2(%x) = %x %= %x)", i, a2, b2, i, a3, b3);
	} while (++i);
	printf("All done.\n");
	return 0;
}
