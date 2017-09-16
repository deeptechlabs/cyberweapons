#include "../src/libcrypt.h"
#include <time.h>

#ifndef WIN32
#define CLK_TCK 1000000.0
#endif

main(argc, argv)
  int argc;
  char *argv[];
{
    Bignum *m, *result;
    RSAKeySet *ksA;
    RSASignature *sig;
    RSAPrivateKey *privkeyA;
    RSAPublicKey *pubkeyA;
    Boolean verified;
    BigInt enc_message;
    int modlen, explen, i, start;
    int exitval = 0;
    BigInt randomStart;
    int seedbytes;


    if (argc < 2) {
	printf("Usage: testRSA modulus-length public-exponent-length (in bits) [optional: seed]\n");
	exit(0);
    }

    modlen = atoi(argv[1]);
    explen = atoi(argv[2]);
    if (argc == 4) {
	    printf("seeding rng with seed.....\n");
	    seed_rng((unsigned char *)argv[3], strlen(argv[3]));
    }
    randomStart = bigInit(0);
    printf("getting randomStart...\n");
    seedbytes = randBytesNeededForRSA(modlen, explen);
    bigRand(seedbytes, randomStart, PSEUDO);
	    
    printf("Generate keys...\n");
    ksA = genRSAKeySet(modlen, explen, randomStart);

    privkeyA = ksA->privateKey;
    pubkeyA = ksA->publicKey;

    m = bigInit(0);
    bigRand(((modlen/8)-1), m, PSEUDO);

    printf("Keys Generated\n");

    /* A encrypts and signs m */

    printf("A encrypting and signing message...\n");
    start = clock();
    for (i=0; i<1; i++)
	enc_message = RSAEncrypt(m, pubkeyA);
    printf("encrypt took %f secs\n", (float)(clock()-start)/(CLK_TCK*i));

    printf("Message Encrypted\n");


    start = clock();
    for (i=0; i<10; i++)
	    sig = (BigInt)RSASign(m, privkeyA);
    printf("signing took %f secs\n", (float)(clock()-start)/(CLK_TCK*i));

    /* B decrypts and verifies signature */

    printf("B decrypting message and verifying signature...\n");
    start = clock();
    for (i=0; i<1; i++)
	result = RSADecrypt(enc_message, privkeyA);
    printf("Decryption took %f secs\n", (float)(clock()-start)/i/CLK_TCK);

    start = clock();
    for (i=0; i<1; i++)
	verified = RSAVerify(m, sig, pubkeyA);
    printf("Verification took %f secs\n", (float)(clock()-start)/CLK_TCK);

    if (bigCompare(m, result) == 0)
	printf("Message decrypted successfully.\n");
    else {
	printf("Message decrypted UN-successfully.\n");
	exitval = 1;
    }

    if (verified == TRUE)
	printf("Signature Verified\n");
    else {
	printf("Signature NOT Verified\n");
	exitval = 2;
    }

    freeBignum(m);
    freeBignum(result);
    freeRSAKeys(ksA);
    freeRSASig(sig);
    freeBignum(enc_message);
    freeBignum(randomStart);

    return 1;
}
