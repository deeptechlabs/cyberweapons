#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#include "md5.h"
#include "md52.h"
 
/* Size of buffer for MD5 speed test data */
 
#define TEST_BLOCK_SIZE	( 20 * 100 )
 
/* Number of bytes of test data to process */
 
#define TEST_BYTES	10000000L
#define TEST_BLOCKS	( TEST_BYTES / TEST_BLOCK_SIZE )

void printhash (unsigned char buf[16])
{
	int i;
	printf("%02x", *buf++);
	for (i = 0; i < 15; i++)
		printf(" %02x", *buf++);
	putchar('\n');
}
 
int main( void )
{
	MD5_CTX ctx1;
	struct MD5Context ctx2;
	unsigned char data[ TEST_BLOCK_SIZE ];
	unsigned char di1[16], di2[16];
	time_t endTime, startTime;
	long i;

	MD5Init(&ctx1);
	MD5Init2(&ctx2);
	MD5Final(di1,&ctx1);
	MD5Final2(di2,&ctx2);
	if (memcmp(di1,di2,sizeof(di1))) {
		printhash(di1);
		printhash(di2);
		puts("Error in MD5 implementation: Test 1 failed");
		exit(-1);
	}
	puts("Test 1 passed");
		
	MD5Init(&ctx1);
	MD5Init2(&ctx2);
	MD5Update(&ctx1, (unsigned char *)"abc", 3);
	MD5Update2(&ctx2, (unsigned char *)"abc", 3);
	MD5Final(di1,&ctx1);
	MD5Final2(di2,&ctx2);
	if (memcmp(di1,di2,sizeof(di1))) {
		printhash(di1);
		printhash(di2);
		puts("Error in MD5 implementation: Test 2 failed");
		exit(-1);
	}
	puts("Test 2 passed");

	MD5Init(&ctx1);
	MD5Init2(&ctx2);
	MD5Update(&ctx1, (unsigned char *)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56 );
	MD5Update2(&ctx2, (unsigned char *)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56 );
	MD5Final(di1,&ctx1);
	MD5Final2(di2,&ctx2);
	if (memcmp(di1,di2,sizeof(di1))) {
		printhash(di1);
		printhash(di2);
		puts("Error in MD5 implementation: Test 3 failed");
		exit(-1);
	}
	puts("Test 3 passed");
		
	MD5Init(&ctx1);
	MD5Init2(&ctx2);
	for(i = 0; i < 1562; i++) {
		MD5Update(&ctx1, (unsigned char *)"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 64);
		MD5Update2(&ctx2, (unsigned char *)"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 64);
	}
		MD5Update(&ctx1, (unsigned char *)"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 32);
		MD5Update2(&ctx2, (unsigned char *)"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 32);
	MD5Final(di1,&ctx1);
	MD5Final2(di2,&ctx2);
	if (memcmp(di1,di2,sizeof(di1))) {
		printhash(di1);
		printhash(di2);
		puts("Error in MD5 implementation: Test 4 failed");
		exit(-1);
	}
	puts("Test 4 passed");

	MD5Init2(&ctx2);
	for (i = 0; i < 4000; i++)
		MD5Update2(&ctx2, (unsigned char *)"aaaaaaaaaaaaaaaaaaaaaaaaa", 25);
	MD5Final2(di2,&ctx2);
	if (memcmp(di1,di2,sizeof(di1))) {
		printhash(di1);
		printhash(di2);
		puts("Error in MD5 implementation: Test 5 failed");
		exit(-1);
	}
	puts("Test 5 passed");

	MD5Init2(&ctx2);
	for (i = 0; i < 800; i++)
		MD5Update2(&ctx2, (unsigned char *)"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 125);
	MD5Final2(di2,&ctx2);
	if (memcmp(di1,di2,sizeof(di1))) {
		printhash(di1);
		printhash(di2);
		puts("Error in MD5 implementation: Test 6 failed");
		exit(-1);
	}
	puts("Test 6 passed");

	/* Now perform time trial, generating MD for 10MB of data.  First,
	   initialize the test data */
	memset( data, 0, TEST_BLOCK_SIZE );

	/* Get start time */
	printf( "MD5 time trial.  Processing %ld characters...\n", TEST_BYTES );
	time( &startTime );

	/* Calculate MD5 message digest in TEST_BLOCK_SIZE byte blocks */
	MD5Init2(&ctx2);
	for(i = TEST_BLOCKS; i > 0; i--)
		MD5Update2(&ctx2, data, TEST_BLOCK_SIZE);
	MD5Final2(di2, &ctx2);

	/* Get finish time and time difference */
	time(&endTime);
	printf("Seconds to process test input: %ld\n", endTime - startTime);
	printf("Characters processed per second: %ld\n", TEST_BYTES / (endTime - startTime));

	return 0;
}
