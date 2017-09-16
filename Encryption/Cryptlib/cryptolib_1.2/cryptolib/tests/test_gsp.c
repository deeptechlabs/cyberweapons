#include "libcrypt.h"
#include <time.h>

#ifndef WIN32
#define CLK_TCK 1000000.0
#endif

int main(argc, argv)
  int argc;
  char *argv[];
{
    BigInt p, q;
    BigInt randomStart;
    char *pwseed;
    int i, acc, numbits, facbits, start, randbytes;

    if (argc < 3) {
	printf("Usage: test_gsp numbits facbits passphrase {optional: primeTestAttempts}\n");
	exit(0);
    }
    numbits = atoi(*++argv);
    facbits = atoi(*++argv);

    if (argc == 4) {
	    pwseed = *++argv;
	    seed_rng((unsigned char *)pwseed, strlen(pwseed));
    }

    randbytes = randBytesNeededForPrime(numbits, facbits, NIST);
    randomStart = bigInit(0);
	printf("Initialize RNG...\n");
    bigRand(randbytes, randomStart, PSEUDO);
	printf("Done.\n");

    if (argc == 5) {
	acc = atoi(*++argv);
	setPrimeTestAttempts(acc);
    }

    p = bigInit(0);
    q = bigInit(0);

    printf("Find 10 %d bit primes with %d bit prime factors of p-1.\n", numbits, facbits);
    start = clock();
    for (i=0; i<10; i++) {
	genStrongPrimeSet(numbits, p, facbits, q, GORDON, randomStart);
/*	genStrongPrimeSet(numbits, p, facbits, q, NIST, randomStart);*/
	bigprint(p);
	randomize(randomStart);
    }
    printf("avg time = %f secs\n", (float)(clock()-start)/i/CLK_TCK);
    printf("p = "); bigprint(p);
    printf("q = "); bigprint(q);

    fflush(stdout);

    freeBignum(p);
    freeBignum(q);
    freeBignum(randomStart);
    
    return 1;

}




