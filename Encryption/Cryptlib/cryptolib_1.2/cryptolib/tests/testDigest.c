#include "libcrypt.h"
#include <time.h>


main(argc, argv)
  int argc;
  char *argv[];
{
    FILE *fp;
    int start, type;
    Bignum *md;
    unsigned char msg[16*1024];

    if (argc < 2) {
	printf("Usage: testDigest type (SHS or MD5 or MD4) [filename]\n");
	exit(1);
    }

    if (strcmp(argv[1], "SHS") == 0)
	type = SHS;
    else if (strcmp(argv[1], "MD5") == 0)
	type = MD5;
    else if (strcmp(argv[1], "MD4") == 0)
	type = MD4;
    else if (strcmp(argv[1], "MD2") == 0)
	type = MD2;
    else {
	printf("Unknown Digest type %s.\n", argv[1]);
	exit(1);
    }
    md = bigInit(0);
    if (argc == 3) {
	fp = fopen(argv[2], "r");
	start = clock();
	fBigMessageDigest(argv[2], md, type);
	printf("%s Digest took %d usecs\n", argv[1], clock()-start);

	bigprint(md);
    }
    else {
	while (1) {

	    printf("Enter message: ");
	    scanf("%s", msg);
	    printf("msg = %s len = %d\n", msg, strlen(msg));
	    if (strcmp(msg, "q") == 0)
		exit(0);

	    start = clock();
	    bigMessageDigest(msg, strlen(msg), md, type);
	    printf("%s Digest took %d usecs\n", argv[1], clock()-start);
	    printf("Digest = "); bigprint(md);
	}
    }	
    freeBignum(md);

    return 1;
}
