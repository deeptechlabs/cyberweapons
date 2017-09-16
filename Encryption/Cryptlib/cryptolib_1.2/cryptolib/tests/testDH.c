#include "libcrypt.h"
#include <time.h>

int main(argc, argv)
  int argc;
  char **argv;
{
	int pbits, qbits, randbytes;
	DiffieHellmanSet *DHset;
	BigInt A_msg1, B_msg1, A_exp, B_exp, A_key, B_key;
	BigInt randomStart;

	if (argc < 3) {
		fprintf(stderr, "usage: testDH primebits subprimebits\n");
		exit(0);
	}
	pbits = atoi(argv[1]);
	qbits = atoi(argv[2]);

	randomStart = bigInit(0);
	randbytes = randBytesNeededForDHSet(pbits, qbits);
	printf("get randomStart...\n");
	bigRand(randbytes, randomStart, PSEUDO);

	A_msg1 = bigInit(0);
	A_exp = bigInit(0);
	A_key = bigInit(0);

	B_msg1 = bigInit(0);
	B_exp = bigInit(0);
	B_key = bigInit(0);

	printf("Generating params: p = %d bits, q = %d bits...\n", pbits, qbits);
	DHset = GenDiffieHellmanSet(pbits, qbits, randomStart);
	printf("Begin exchange...\n");

	reset_big(randomStart, 0);
	randbytes = randBytesNeededForDHInit(qbits);
	bigRand(randbytes, randomStart, PSEUDO);
	printf("A stage 1...\n");
	DiffieHellmanInit(DHset, A_exp, A_msg1, randomStart);
	randomize(randomStart);
	printf("B stage 1...\n");
	DiffieHellmanInit(DHset, B_exp, B_msg1, randomStart);

	printf("B stage 2...\n");
	DiffieHellmanGenKey(DHset, B_msg1, A_exp, A_key);
	printf("B stage 2...\n");
	DiffieHellmanGenKey(DHset, A_msg1, B_exp, B_key);

	if (bigCompare(A_key, B_key) != 0) {
		printf("Diffie Hellman exchange failed.\n");
	}
	else
		printf("Key = "); bigprint(A_key);

	freeBignum(A_msg1);
	freeBignum(A_exp);
	freeBignum(A_key);

	freeBignum(B_msg1);
	freeBignum(B_exp);
	freeBignum(B_key);

	freeBignum(randomStart);
	freeDiffieHellmanSet(DHset);

	return 1;
}
