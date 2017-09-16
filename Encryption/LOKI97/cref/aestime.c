/*
 * aestime - time how long computations take on AES algorithm
 *	   for cipher init, encrypt 1Mb, decrypt 1Mb, set 1000 key pairs
 *
 *         Customise the ALG name and include file below and link with
 *         any alg satisfying the AES C-API.
 *
 * written by Lawrie Brown <lawre.Brown@adfa.oz.au> / May 1998
 */

#define ALG "LOKI97"		/*** Customise - algorithm name ***/
#include "loki97.h"		/*** Customise - algorithm header file ***/

#include <time.h>
#define MILLICLKS	(CLOCKS_PER_SEC/1000.0)

main()
{
    printf("Alg\tKey/Blk\tInit\tEncrypt 1Mb\tDecrypt 1Mb\tKey Init (1000 pairs)\n");
    printf("\t\tTime ms\tTime ms Kbps\tTime ms Kbps\tTime ms Keys/ms\n");
    timealg(128);
    timealg(192);
    timealg(256);

}


/*
 * timealg(keysize) - time AES algorithm using specified keysize
 */
timealg(int keysize)
{
    char *key = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
    BYTE plain[] =	{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, /* 128 bytes */
			 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
			 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
			 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
			 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
			 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
			 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
			 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    BYTE		temp[128];				/* 128 bytes */
    int			kbnum = 1024 / sizeof(plain);	/* num plain in 1Kb */
    keyInstance		enc_key, dec_key;	/* AES keyInstances */
    cipherInstance	aes_cipher;		/* AES cipherInstance */
    int			i, j;			/* misc counters */
    clock_t		start,finish;		/* time values */
    unsigned long	duration;

    /* print alg name and block/key size */
    printf("%s\t%d/%d\t", ALG, keysize, BLOCK_SIZE*8);

    /* Init AES cipher in ECB mode */
    start = clock();
    cipherInit(&aes_cipher, MODE_ECB, NULL);
    finish = clock();
    duration = (finish-start)/MILLICLKS;
    printf("%ld\t", duration);

    /* Time encrypt */
    makeKey(&enc_key, DIR_ENCRYPT, keysize, key);
    start = clock();
    for(i=0;i<kbnum;i++)
        for(j=0;j<1024;j++)
	    blockEncrypt(&aes_cipher, &enc_key, plain, sizeof(plain)*8, temp);
    finish = clock();
    duration = (finish-start)/MILLICLKS;
    printf("%ld\t", duration);
    printf("%4.1lf\t", (double)(8*1024*1024/duration));

    /* Time decrypt */
    makeKey(&dec_key, DIR_DECRYPT, keysize, key);
    start = clock();
    for(i=0;i<kbnum;i++)
        for(j=0;j<1024;j++)
	    blockDecrypt(&aes_cipher, &dec_key, plain, sizeof(plain)*8, temp);
    finish = clock();
    duration = (finish-start)/MILLICLKS;
    printf("%ld\t", duration);
    printf("%4.1lf\t", (double)(8*1024*1024/duration));

    /* Time Key Inits */
    start = clock();
    for(i=0;i<1000;i++)
	makeKey(&enc_key, DIR_ENCRYPT, keysize, key);
	makeKey(&dec_key, DIR_DECRYPT, keysize, key);
    finish = clock();
    duration = (finish-start)/MILLICLKS;
    printf("%ld\t", duration/2);
    printf("%4.1lf\n", (double)(2000/duration));
}

