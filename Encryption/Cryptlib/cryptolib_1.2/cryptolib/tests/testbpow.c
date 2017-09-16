#include "libcrypt.h"
#include <time.h>

#ifndef WIN32
#define CLK_TCK 1000000.0
#endif
    
int main(argc, argv)
  int argc;
  char **argv;
{
    BigInt a, b, c, d, m, n;
    Table *t, *g1, *g2;
    int i, start, modlen, explen, msglen;
    char *pwseed;
    int randbytes;
    BigInt randStart;

    if (argc < 4) {
	printf("Usage: testbpow modulus-bit-length exponent-bit-length msg-bit-length [passphrase]\n");
	exit(0);
    }

    if (argc == 5) {
	pwseed = argv[4];
	seed_rng((unsigned char *)pwseed, strlen(pwseed));
    }

    modlen = atoi(argv[1]);
    modlen = modlen / 8;
    explen = atoi(argv[2]);
    explen = explen / 8;
    if (explen == 0)
	explen = 1;
    msglen = atoi(argv[3]) / 8;

    a = bigInit(3);
    b = bigInit(0x10001);
    c = bigInit(0);
    d = bigInit(0);

    m = bigInit(0);
    n = bigInit(0);

    randStart = bigInit(0);
    randbytes = modlen;

	printf("Starting RNG....\n");
    bigRand(randbytes, randStart, PSEUDO);
	printf("Done.\n");

    bigRand(modlen, c, PSEUDO);
    if (EVEN(c)) {
	printf("Fix even modulus\n");
	bigAdd(c, one, c);
    }
    bigRand(msglen, a, PSEUDO);
    getRandBetween(zero, c, b, PSEUDO, randStart);

    goto single;
    {
	    BigInt a1, a2, b1, b2, nm;
	    a1 = bigInit(0);
	    a2 = bigInit(0);
	    b1 = bigInit(0xabcd);
	    b2 = bigInit(0x1234);
	    n = bigInit(0);
	    nm = bigInit(0);
	    bigRand(msglen, a1, PSEUDO);
	    bigRand(msglen, a2, PSEUDO);

	    bigRand(explen, b1, PSEUDO);
	    bigRand(explen-12, b2, PSEUDO);

	    printf("DOUBLE BIGPOWS:\n");
	    start = clock();
	    for (i=0; i<1; i++) {
		    bigPow(a1, b1, c, n);
		    bigPow(a2, b2, c, m);
		    bigMultiply(n, m, nm);
		    bigMod(nm, c, nm);
	    }
	    printf("PROD of bigPows: result took %f secs\n", (float)(clock()-start)/i/CLK_TCK);
	    printf("res = "); bigprint(nm);

	    start = clock();
	    for (i=0; i<1; i++) {
		    double_bigPow(a1, a2, b1, b2, c, nm);
	    }
	    printf("Double_bigPow  : result took %f secs\n", (float)(clock()-start)/i/CLK_TCK);
	    printf("res = "); bigprint(nm);

	    g1 = g16_bigpow(a1, c, 8*LENGTH(b1));
	    g2 = g16_bigpow(a2, c, 8*LENGTH(b2));

	    start = clock();
	    for (i=0; i<1; i++) {
		    double_brickell_bigpow(g1, g2, b1, b2, c, nm);
	    }
	    printf("Double Brickell: result took %f secs\n", (clock()-start)/i/CLK_TCK);
	    printf("res = "); bigprint(nm);

	    printf("\n\n");
    }

 single:

    printf("a = "); bigprint(a);
    printf("b = "); bigprint(b);
    printf("c = "); bigprint(c);

    start = clock();
    for (i=0; i<10; i++) {
	    bigPow(a, b, c, m);
    }

    printf("bigpow took %f secs\n", (float)((clock()-start))/CLK_TCK/i);
    printf("a^b mod c = "); bigprint(m);

    start = clock();
    for (i=0; i<1; i++) {
	bigCube(a, c, m);
    }

    printf("\nbigCube took %f secs\n", (float)(clock()-start)/i/CLK_TCK);
    printf("a^3 mod c = "); bigprint(m);

    start = clock();
    for (i=0; i<1; i++) {
	bigMultiply(a, a, m);
	bigMod(m, c, m);
    }

    printf("\nbigSquare took %f secs\n", (float)(clock()-start)/i/CLK_TCK);
    printf("a^2 mod c = "); bigprint(m);

    printf("\n\n");

    start = clock();
    for (i=0; i<1; i++)
	    t = g16_bigpow(a, c, 8*LENGTH(b));
    printf("table took %f secs\n", (float)(clock()-start)/i/CLK_TCK);

    start = clock();

    for (i=0; i<1; i++)
	brickell_bigpow(t, b, c, n);

    printf("brickell bigpow took %f secs\n", (float)((clock()-start)/i/CLK_TCK));
    printf("a^b mod c = "); bigprint(n);

    freeTable(t);
    freeBignum(a);
    freeBignum(b);
    freeBignum(c);
    freeBignum(d);
    freeBignum(m);
    freeBignum(n);
    freeBignum(randStart);


	return 1;
}

