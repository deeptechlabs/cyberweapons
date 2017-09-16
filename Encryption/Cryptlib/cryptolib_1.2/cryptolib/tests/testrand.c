#include <stdio.h>
#include "libcrypt.h"

main(argc, argv)
  int argc;
  char *argv[];
{
    int numbytes, i, type;
    Bignum *n;
    unsigned char buf[1024], *pwseed;
	char *filename;
    FILE *fp;

    if (argc < 4) {
	    printf("Usage: testrand numbytes type (PSEUDO or REALLY) (BYTES or BIGS) (optional: PASSPHRASE)\n");
	    printf("If BYTES are specified, 1024*1024 bytes ar written to /tmp/pseudorandbytes or /tmp/truerandbytes\n");
	    exit(0);
    }

    if (strcmp(argv[2], "PSEUDO") == 0) {
	    if (argc == 5) {
		    pwseed = argv[4];
		    seed_rng((unsigned char *)pwseed, strlen(pwseed));
		    printf("seed = %s\n", pwseed);
	    }
	    type = PSEUDO;
    }
    else if (strcmp(argv[2], "REALLY") == 0)
	    type = REALLY;
    else {
	    printf("Usage: testrand numbytes type (PSEUDO or REALLY) (BYTES or BIGS) (optional: PASSPHRASE)\n");
	    printf("If BYTES are specified, 1024*1024 bytes ar written to /tmp/pseudorandbytes or /tmp/truerandbytes\n");
	    exit(0);
    }

    if (strcmp(argv[3], "BYTES") == 0)
	    goto _BYTES;
    else if (strcmp(argv[3], "BIGS") == 0)
	    goto _BIGS;
    else {
	    printf("Usage: testrand numbytes type (PSEUDO or REALLY) (BYTES or BIGS) (optional: PASSPHRASE)\n");
	    printf("If BYTES are specified, 1024*1024 bytes ar written to /tmp/pseudorandbytes or /tmp/truerandbytes\n");
	    exit(0);
    }

    _BIGS:

    numbytes = atoi(argv[1]);
    n = bigInit(0);

	/* This is just to remind user that it takes awhile for
	    the first call to desRandom() inside bigRand.  Normally
		you don't have to do this...the seeding happens by
		default unless you call seed_rng(unsigned char *seed, int seedlen)
		with seedlen = 64 bytes.
	*/
	if (type == PSEUDO) {
		printf("seeding RNG...\n");
		bigRand(numbytes, n, type);
		printf("done.\n");
	}

    for (i=0; i<10; i++) {
	bigRand(numbytes, n, type);
	bigprint(n);
    }
    freeBignum(n);

    exit(0);

    _BYTES:
    if (type == REALLY)
	filename = "/tmp/truerandbytes";
    else
	filename = "/tmp/pseudorandbytes";
	
    fp = fopen(filename, "w");

    i = 1024;
    while (i--) {
	randomBytes(buf, 1024, type);
	fwrite(buf, 1, 1024, fp);
    }

    fclose(fp);

    return 1;
}


