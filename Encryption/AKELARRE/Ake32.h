// ake32.h

#include <stdio.h>
#include <time.h>

#define word16		unsigned short int
#define word32		unsigned long int

#define ROUNDS			1	 // this sets the number of encryption rounds
#define SUBKEYS			(13*ROUNDS+9) // number of subkeys that will be generated
#define ITERATIONS		5000 // number of times you want to run the algorithm
#define DWORDS_IN_KEY	4 // it is the number of 32-bit word in the user-key

// these are the constants used to add a non-zero value to the userkey
const unsigned long constant[] = {	0XA49ED284,
							0X735203DE,
							0X43FE9AB1,
							0XA61BD2F9,
							0XA946E175,
							0XFDA506B3,
							0XC71FEB25,
							0XE1F079BD,
							0XBA96FDE1,
							0XF5837AC1,
							0XB87D64E5,
							0XC92F670B,
							0XF1BC8EA3,
							0X910EA8D7,
							0X8B957D3F,
							0XCE53B9A3,
							0XECF76A59,
							0X8B67FD95,
							0XBEA43971,
							0XF261D93B };

// these primes are used during the key-expansion when performing square mod operations
const unsigned long prime[] = {	0XFFF1D567,
						0XFFF208C7,
						0XFFFFD487,
						0XFFF75587,
						0XFFF8C7D7,
						0XFFF8F207,
						0XFFF90767,
						0XFFFC59E7,
						0XFFFB1D07,
						0XFFFDB3A7,
						0XFFFA6157,
						0XFFFEA977,
						0XFFFD78C7,
						0XFFFC0FD7,
						0XFFFEFFB7,
						0XFFFFD487,
						0XFFF923B7,
						0XFFFB40A7,
						0XFFFCE867,
						0XFFF9B6B7	};

// define a user type for the array of subkeys
typedef word32 ake32key[SUBKEYS];