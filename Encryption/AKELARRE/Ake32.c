// ake32.c

#include "ake32.h"

// performs n ^ 2 mod p operation 
word32 squaremod( word32 n, word32 p )
{
	word32	k, sum, result = 0;
	word32	partial;
	int		carry = 0;

	// copy 'n' into 'sum' and into 'bits' and set 'n' to zero
	k = sum = n;

	// extract the bits from the right part of 'bits'
	// for each bit to 1 we add 'sum' to 'n'
	// 'sum' is shifted to the left in each step
	while ( k > 0 ) {
		if ( k & 1 ) {	// if bit0 == 1
							// then we add 'sum' to 'result'
			partial = result + sum;
			if ( (partial < result) || (partial < sum) )
				carry = 1;
			result = partial;
			// check if 'result' is greater than 'p'
			if ( (result > p) || carry ) {// if result>p then result-p */
				result -= p;
				carry = 0;
			}
		}
		// Multiply sum by 2
		if ( sum & 0x80000000 )
			carry = 1;
		sum <<= 1;
		
		// check if sum is greater than 'p'
		if ( (sum > p) || carry ) {	// if sum>p then sum-p
			sum -= p;
			carry = 0;
		}
		k >>= 1;
	}
	return result;
}

// performs the leftwise rotation operation on a 128-bit word
void rotl128( word32 * a, int b )
{
	word32 temp1, temp2;
	register int i;

	if ( b < 32 ) {
		temp1 = a[3];
		for ( i = 3; i > 0; i-- ) {
			a[i] <<= b;
			if ( b != 0  )
				a[i] |= a[i-1] >> (32-b);
		}
		a[0] <<= b;
		if ( b != 0  )
			a[0] |= temp1 >> (32-b);
	}
	else if ( b < 64 ) {
		temp1 = a[3];
		temp2 = a[2];

		for ( i = 3; i > 1; i-- ) {
			a[i] = 0;
			a[i] = a[i-1] << (b-32);
			if ( b != 32 )
				a[i] |= a[i-2] >> (64-b);
		}
		a[1] = 0;
		a[1] = a[0] << (b-32);
		if ( b != 32 )
			a[1] |= temp1 >> (64-b);
		a[0] = 0;
		a[0] = temp1 << (b-32);
		if ( b != 32 )
			a[0] |= temp2 >> (64-b);
	}
	else if ( b < 96 ) {
		temp1 = a[0];
		temp2 = a[1];

		b = 128-b;
		for ( i = 0; i < 2; i++ ) {
			a[i] = 0;
			if ( b != 64 )
				a[i] = a[i+1] >> (b-32);
			a[i] |= a[i+2] << (64-b);
		}
		a[2] = 0;
		if ( b != 64 )
			a[2] = a[3] >> (b-32);
		a[2] |= temp1 << (64-b);
		a[3] = 0;
		if ( b != 64 )
			a[3] = temp1 >> (b-32);
		a[3] |= temp2 << (64-b);
	}
	else {
		temp1 = a[0];

		b = 128-b;
		for ( i = 0; i < 3; i++ ) {
			if ( b != 32 )
				a[i] >>= b;
			else 
				a[i] = 0;
			a[i] |= a[i+1] << (32-b);
		}
		if ( b != 32 )
			a[3] >>= b;
		else 
			a[3] = 0;
		a[3] |= temp1 << (32-b);
	}
}

// rotate left the 31 most significant bits
word32 rotl31( word32 x, int y )
{
	word32 bit = 0;

	bit = x & 0x1;
	x &= 0xfffffffe;
	return ((x<<(y&0x1f)) | (x>>(31-(y&0x1f))))|bit;
}

// rotate left the 31 less significant bits
word32 rotl1( word32 x, int y )
{
	word32 bit = 0;

	bit = x & 0x80000000;
	x &= 0x7fffffff;
	return ((x<<(y&0x1f)) | (x>>(31-(y&0x1f))))|bit;
}

// generate the encryption subkeys from the user-key
void en_key_ake32(word32 *userkey, word32 *EK)
{
	register int	i;
	word32			t[DWORDS_IN_KEY];

	// First we initialize the auxiliar variables t(i)
	// t(i) = (k(i)+a(i))^2 mod p(i) 
	for ( i = 0; i < DWORDS_IN_KEY; i++ )
		t[i] = squaremod( userkey[i]+constant[i], prime[i] );

	// Next we calculate as many subkeys as necessary
	for ( i = 0; i < SUBKEYS; i++ ) {
		// K(i) = t(i) ^ t(i+2)
		EK[i] = t[i%DWORDS_IN_KEY] ^ t[(i+2)%DWORDS_IN_KEY];

		// t(i) = (t(i) ^ t(i+1)) mod p(i)
		t[i%DWORDS_IN_KEY]		= 
			squaremod( t[i%DWORDS_IN_KEY]^t[(i+1)%DWORDS_IN_KEY],
			prime[i%DWORDS_IN_KEY] );

		// t(i+2) = (t(i+2) ^ t(i+3)) mod p(i+2)
		t[(i+2)%DWORDS_IN_KEY]	= 
			squaremod( t[(i+2)%DWORDS_IN_KEY]^t[(i+3)%DWORDS_IN_KEY],
			prime[(i+2)%DWORDS_IN_KEY] );
	}
}

// generates the decryption subkeys from the encryption subkeys
void de_key_ake32(ake32key EK, ake32key DK)
{
   register int i, j;
   word32 t1, t2, t3, t[11];
   ake32key T;				 
   word32 *p=T+SUBKEYS;
   t1=-*EK++;
   t2=*EK++;
   t3=*EK++;
   *--p=-*EK++;
   *--p=t3;
   *--p=t2;
   *--p=t1;
	*--p=128-(*EK++)&0x7f;

	for (j=0;j<ROUNDS;j++)
	{
		for ( i = 0; i < 11; i++ )
			t[i]=*EK++;
		*--p=*EK++;
		for ( i = 10; i >= 0; i-- )
			*--p=t[i];
		*--p=128-(*EK++)&0x7f;
   }
   t1=-*EK++;
   t2=*EK++;
   t3=*EK++;
   *--p=-*EK++;
   *--p=t3;
   *--p=t2;
   *--p=t1;
   
   //copy and destroy temp copy
   for(j=0,p=T;j<SUBKEYS;j++)
   {
      *DK++=*p;
      *p++=0;
   }
}																				

// encrypts the input text into the output ciphertext using the subkeys
void cipher_ake32( word32 in[4], word32 out[4], register ake32key EK )
{
	word32 x[4], t1, t2;
	int r = ROUNDS;
	x[0] = *in++; 
	x[1] = *in++;
	x[2] = *in++;
	x[3] = *in;

	// Initial rotation and addition and XOR operations
	x[0] += *EK++;
	x[1] ^= *EK++;
	x[2] ^= *EK++;
	x[3] += *EK++;

	do {
		rotl128( x, (*EK++)&0x7f );
		t1 = x[0] ^ x[2];
		t2 = x[1] ^ x[3];

		// Next, the additions-rotations
		t2 = rotl31( t2, t1 );
		t2 += *EK++;
		t2 = rotl1( t2, t1 >> 5  );
		t2 += *EK++;
		t2 = rotl31( t2, t1 >> 10  );
		t2 += *EK++;
		t2 = rotl1( t2, t1 >> 15 );
		t2 += *EK++;
		t2 = rotl31( t2, (t1 >> 20)&0xf  );
		t2 += *EK++;
		t2 = rotl1( t2, (t1 >> 24)&0xf  );
		t2 += *EK++;
		t2 = rotl31( t2, (t1 >> 28)&0xf );

		t1 = rotl1( t1, t2 );
		t1 += *EK++;
		t1 = rotl31( t1, t2 >> 5  );
		t1 += *EK++;
		t1 = rotl1( t1, t2 >> 10  );
		t1 += *EK++;
		t1 = rotl31( t1, t2 >> 15 );
		t1 += *EK++;
		t1 = rotl1( t1, (t2 >> 20)&0xf  );
		t1 += *EK++;
		t1 = rotl31( t1, (t2 >> 24)&0xf  );
		t1 += *EK++;
		t1 = rotl1( t1, (t2 >> 28)&0xf );
		x[0] ^= t2;
		x[2] ^= t2;
		x[1] ^= t1;
		x[3] ^= t1;
	} while (--r);

	// Final rotation and addition and XOR operations
	rotl128( x, (*EK++)&0x7f );
	*out++ = x[0] + *EK++;
	*out++ = x[1] ^ *EK++;
	*out++ = x[2] ^ *EK++;
	*out = x[3] + *EK;
}

int main ( )
{
	word32 userkey[DWORDS_IN_KEY] = { 0x0000000,0x0000,0x0000,0X0000 };
	clock_t start, finish;
	word32 AA[4],BB[4],CC[4];
	ake32key EK,DK;
	register long l;
	FILE *fich;

	AA[0] = AA[1] = AA[2] = 0;
	AA[3] = 0x10000000;
   en_key_ake32(userkey,EK);
	fich = fopen( "clave3.txt", "wt" );
	for ( l = 0; l < SUBKEYS; l++ )
		fprintf( fich, "EK[%d] = %08X\n", l, EK[l] );
   de_key_ake32(EK,DK);
	fclose( fich );

	printf( "AA = %08X %08X %08X %08X\n", AA[0], AA[1], AA[2], AA[3] );	
	printf("\nEncrypting %lu words: ", ITERATIONS );
	start = clock( );
	cipher_ake32(AA,BB,EK);
	/*for ( l = 0; l < ITERATIONS; l++ )
		cipher_ake32(BB, BB, EK);*/
	finish = clock( ) - start;
	fich = fopen( "crypt.txt", "at" );
	fprintf( fich, "BB = %08X %08X %08X %08X\n", BB[0], BB[1], BB[2], BB[3] );
	fclose( fich );
	printf( "BB = %08X %08X %08X %08X\n", BB[0], BB[1], BB[2], BB[3] );
	printf( "%2.3f seconds\n", (double) finish/CLK_TCK );

	printf("\nDecrypting %lu words: ", ITERATIONS );
	start = clock( );
	cipher_ake32( BB, CC, DK );
	/*for ( l = 0; l < ITERATIONS; l++ )
		cipher_ake32( CC, CC, DK );*/
	finish = clock( ) - start;
	printf( "CC = %08X %08X %08X %08X\n", CC[0], CC[1], CC[2], CC[3] );
	printf( "%2.3f seconds\n", (double) finish/CLK_TCK );

  	getchar( );

   return 0;
}