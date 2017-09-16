#include "libcrypt.h"
#include <time.h>

#ifndef WIN32
#define CLK_TCK 1000000.0
#endif


int main(argc, argv)
  int argc;
  char *argv[];
{
    Bignum *m, *result, *p, *q, *alpha;
    EGParams *params;
    EGKeySet *ksA, *ksB;
    EGSignature *sig;
    EGPrivateKey *privkeyA, *privkeyB;
    EGPublicKey *pubkeyA, *pubkeyB;
    Boolean verified;
    BigInt enc_message;
    BigInt randomStart;
    int randbytes;
    int primeLen, subPrimeLen, start;
    int exitval = 0;

    if (argc < 3) {
	printf("Usage: testEG primeLen subprimeLen (in bits)\n");
	exit(0);
    }
    primeLen = atoi(argv[1]);
    subPrimeLen = atoi(argv[2]);
    randomStart = bigInit(0);
    randbytes = randBytesNeededForEGParams(primeLen, subPrimeLen);
	printf("Getting random bytes....\n");
    bigRand(randbytes, randomStart, PSEUDO);
	printf("Getting params....\n");
    params = genEGParams(primeLen, subPrimeLen, randomStart);
    printf("got params...\n");

    p = params->p;
    q = params->q;
    alpha = params->alpha;

    reset_big(randomStart, 0);
    randbytes = randBytesNeededForEGKeySet(subPrimeLen);
    bigRand(randbytes, randomStart, PSEUDO);

    ksA = genEGKeySet(params, primeLen, subPrimeLen, randomStart);
    privkeyA = ksA->privateKey;
    pubkeyA = ksA->publicKey;
    printf("got key set A\n");

    randomize(randomStart);
    ksB = genEGKeySet(params, primeLen, subPrimeLen, randomStart);
    privkeyB = ksB->privateKey;
    pubkeyB = ksB->publicKey;
    printf("got key set B\n");

    m = bigInit(0);
    reset_big(randomStart, 0);
    randbytes = randBytesNeededForEGEncrypt(subPrimeLen);
    bigRand(randbytes, randomStart, PSEUDO);

    printf("Keys Generated\n");

    /* A encrypts and signs m */
    printf("A encrypting and signing message...\n");
    start = clock();
    enc_message = EGEncrypt(m, pubkeyB, randomStart);
    printf("encrypt took %f secs\n", (float)(clock()-start)/CLK_TCK);

    printf("Message Encrypted\n");
    reset_big(randomStart, 0);
    randbytes = randBytesNeededForEGSign(subPrimeLen);
    bigRand(randbytes, randomStart, PSEUDO);

    start = clock();
    sig = (EGSignature *)EGSign(m, privkeyA, randomStart);
    printf("Signature took %f msecs\n", (float)(clock()-start)/CLK_TCK);

    /* B decrypts and verifies signature */
    printf("B decrypting message and verifying signature...\n");
    start = clock();
    result = EGDecrypt(enc_message, privkeyB);
    printf("Decryption took %f secs\n", (float)(clock()-start)/CLK_TCK);

    start = clock();
    verified = EGVerify(result, (EGSignature *)sig, pubkeyA);
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
    freeEGKeys(ksA);
    freeEGKeys(ksB);
    freeEGSig(sig);
    freeBignum(enc_message);
    freeEGParams(params);

    return 1;
}
