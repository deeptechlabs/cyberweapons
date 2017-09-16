#include "libcrypt.h"

unsigned char a[1000000];
main() {
	int i;
	SHS_CTX context;

	for (i=0; i<1000000; i++)
		a[i] = 'a';

	i = 0;
	shsInit(&context);
	
	while (i<1000000) {
		shsUpdate(&context, a, 4);
		i += 4;
	}
	shsFinal(&context);
printf("totlen = %d\n", context.totalLength);

	for (i=0; i<5; i++)
		printf("%08lx ", context.h[i]);
	printf("\n\n");

	shsInit(&context);
	shsUpdate(&context, a, 1000000);
	shsFinal(&context);

	for (i=0; i<5; i++)
		printf("%08lx ", context.h[i]);
	printf("\n\n");

}
