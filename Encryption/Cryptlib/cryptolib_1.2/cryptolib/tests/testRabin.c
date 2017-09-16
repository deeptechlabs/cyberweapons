#include "libcrypt.h"
#include <time.h>

#ifndef WIN32
#define CLK_TCK 1000000.0
#endif

main(argc, argv)
  int argc;
  char **argv;
{
	int modlen, msglen, digestType, digestLen;
	BigInt message, enc_message, dec_message;
	BigInt sig;
	RabinKeySet *ks;
	RabinPublicKey *pubkey;
	RabinPrivateKey *privkey;
	int start, i, randbytes;
	BigInt randomStart;

	if (argc < 4) {
		fprintf(stderr, "usage: testRabin modbits msgbit digestType [SHS, MD2, MD4, MD5]\n");
		fprintf(stderr, "msgbits < modbits + digest bits\n");
		exit(0);
	}

	modlen = atoi(argv[1]);
	msglen = atoi(argv[2]);
	randomStart = bigInit(0);
	randbytes = randBytesNeededForRabinSet(modlen);

	if (strcmp(argv[3], "SHS") == 0) {
		digestType = SHS;
		digestLen = 20;
	}
	else if (strcmp(argv[3], "MD5") == 0) {
		digestType = MD5;
		digestLen = 16;
	}
	else if (strcmp(argv[3], "MD4") == 0) {
		digestType = MD4;
		digestLen = 16;
	}
	else if (strcmp(argv[3], "MD2") == 0) {
		digestType = MD2;
		digestLen = 16;
	}
	else {
		printf("Don't know Message Digest %s, using SHS.\n", argv[3]);
		digestType = SHS;
		digestLen = 20;
	}

	printf("Getting randomStart...\n");
	start = clock();
	bigRand(randbytes, randomStart, PSEUDO);
	printf("RNG prep took %f secs\n", (float)(clock()-start)/CLK_TCK);

	printf("Generate keys...%d bits\n", modlen);
printf("got keys..\n");
	start = clock();
	ks = genRabinKeySet(modlen, randomStart);
	printf("Key Gen took %f secs\n", (float)(clock()-start)/CLK_TCK);
	pubkey = ks->publicKey;
	privkey = ks->privateKey;

	message = bigInit(0);
	bigRand(msglen/8, message, PSEUDO);
	printf("message = "); bigprint(message);

	reset_big(randomStart, 0);
	randbytes = randBytesNeededForRabinEncrypt(modlen);
	bigRand(randbytes, randomStart, PSEUDO);

	start = clock();
	for (i=0; i<1; i++)
		enc_message = RabinEncrypt(message, pubkey, digestType, digestLen, randomStart);
	printf("Enc took %f secs\n", (float)(clock()-start)/i/CLK_TCK);
	printf("encrypted message = "); bigprint(enc_message);

	start = clock();
	for (i=0; i<1; i++)
		dec_message = RabinDecrypt(enc_message, privkey, digestType, digestLen);
	printf("Dec took %f secs\n", (float)(clock()-start)/i/CLK_TCK);
	printf("dec_message = "); bigprint(dec_message);

	if (bigCompare(message, dec_message) != 0)
		printf("problem...decryption failed.\n");
	printf("\n\n");

	reset_big(randomStart, 0);
	randbytes = randBytesNeededForRabinSign(modlen);
	bigRand(randbytes, randomStart, PSEUDO);

	start = clock();
	for (i=0; i<1; i++)
		sig = RabinSign(message, privkey, digestType, digestLen, randomStart);
	printf("Sign took %f secs\n", (float)(clock()-start)/i/CLK_TCK);
	printf("sig = "); bigprint(sig);

	if (RabinVerify(message, sig, pubkey, digestType, digestLen) == TRUE)
		printf("Verification Succeeded\n");
	else
		printf("Verification Failed\n");

	freeBignum(message);
	freeBignum(randomStart);
	freeBignum(enc_message);
	freeBignum(dec_message);
	freeRabinSignature(sig);
	freeRabinKeySet(ks);

	return 1;
}

