#include "libcrypt.h"
#include <time.h>

#ifndef WIN32
#define CLK_TCK 1000000.0
#endif

#define BUFSIZE 16*1024

main(argc, argv)
  int argc;
  char *argv[];
{
    DSAKeySet *ks;
    DSAPublicKey *pubkey;
    DSAPrivateKey *privkey;
    FILE *pubfile, *privfile;
    DSASignature *sig;
    DSAParams *params;
    Boolean verified;
    int primeLen, subprimeLen, i, start;
    BigInt md;
    unsigned char buffer[BUFSIZE], **bptr;
    BigInt randomStart;
    int randbytes;


    if (argc < 4) {
	    printf("To generate keys: testDSA primeLen subprimeLen pubKeyFileName privKeyFileName fileToBeDigested\n");
	    printf("To use existing keys: testDSA pubKeyFileName privKeyFileName fileToBeDigested\n");
	    exit(0);
    }

    randomStart = bigInit(0);

    if (argc == 6)
	    goto genKeys;
    else
	    goto existingKeys;

 genKeys:
    printf("Generating keys...\n");
    primeLen = atoi(*++argv);
    subprimeLen = atoi(*++argv);
    printf("p = %d bits, q = %d bits\n", primeLen, subprimeLen);
    randbytes = randBytesNeededForDSAParams(primeLen, subprimeLen);
    bigRand(randbytes, randomStart, PSEUDO);

    params = genDSAParams(primeLen, subprimeLen, randomStart);
    printf("Got Params...\n");
    reset_big(randomStart, 0);
    randbytes = randBytesNeededForDSAKeySet(subprimeLen);
    bigRand(randbytes, randomStart, PSEUDO);

    ks = genDSAKeySet(params, primeLen, subprimeLen, randomStart);
    printf("Got keys...\n");
    memset(buffer, 0, BUFSIZE);
    bptr = (unsigned char **)malloc(sizeof(unsigned char *));
    *bptr = buffer;
    pubfile = fopen(*++argv, "w");
    bufPutDSAPublicKey(ks->publicKey, bptr);
    fwrite(buffer, 1, BUFSIZE, pubfile);
    fclose(pubfile);
    free((char *)bptr);

    memset(buffer, 0, BUFSIZE);
    bptr = (unsigned char **)malloc(sizeof(unsigned char *));
    *bptr = buffer;
    privfile = fopen(*++argv, "w");
    bufPutDSAPrivateKey(ks->privateKey, bptr);
    fwrite(buffer, 1, BUFSIZE, privfile);
    fclose(privfile);
    free((char *)bptr);

    pubkey = ks->publicKey;
    privkey = ks->privateKey;

    freeDSAParams(params);
    goto DSAtest;


 existingKeys:

    ks = (DSAKeySet *)malloc(sizeof(DSAKeySet));
    memset(buffer, 0, BUFSIZE);
    bptr = (unsigned char **)malloc(sizeof(unsigned char *));
    *bptr = buffer;
    pubfile = fopen(*++argv, "r");
    if (pubfile == NULL) {
	    printf("%s doesn't exist\n", argv[1]);
	    exit(1);
    }
    fread(buffer, 1, BUFSIZE, pubfile);
    pubkey = bufGetDSAPublicKey(bptr);
    fclose(pubfile);
    free((char *)bptr);

    memset(buffer, 0, BUFSIZE);
    bptr = (unsigned char **)malloc(sizeof(unsigned char *));
    *bptr = buffer;
    privfile = fopen(*++argv, "r");
    if (privfile == NULL) {
	    printf("%s doesn't exist\n", argv[2]);
	    exit(2);
    }
    fread(buffer, 1, BUFSIZE, privfile);
    privkey = bufGetDSAPrivateKey(bptr);
    fclose(privfile);
    free((char *)bptr);
    ks->publicKey = pubkey;
    ks->privateKey = privkey;

    printf("Got keys..\n");
    goto DSAtest;

 DSAtest:
    
    md = bigInit(0);
    bigRand(8, md, PSEUDO);    

	printf("Digesting %s\n",*++argv);
    fBigMessageDigest(*argv, md, SHS);

    printf("md = "); bigprint(md);

    reset_big(randomStart, 0);
    randbytes = randBytesNeededForDSASign(bigBits(pubkey->q));
    printf("get %d bytes for randomStart...\n", randbytes);
    bigRand(randbytes, randomStart, PSEUDO);

    start = clock();
    sig = DSASign(md, privkey, randomStart);
    
    printf("Signing took %f secs\n", (float)((clock() - start)/CLK_TCK));
    printf("Signature Generated\n"); fflush(stdout);

    /* verify */
    start = clock();
	verified = DSAVerify(md, sig, pubkey);

    printf("Verification took %f secs\n", (float)((clock() - start)/CLK_TCK));

    if (verified == TRUE) {
	printf("Signature Verified\n"); fflush(stdout);
    }
    else {
	printf("Signature NOT Verified\n"); fflush(stdout);
    }

    freeDSAKeys(ks);
    freeDSASig(sig);
    freeBignum(md);
    freeBignum(randomStart);

    return 1;
}
