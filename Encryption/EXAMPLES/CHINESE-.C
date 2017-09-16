/* "totient() is left as an exercise for the reader..."
   (N.B.: totient is also know as Euler's phi function.)
		--Ken Pizzini
		ken@halcyon.com
*/
/*
I WOULD LIKE A CODE FRAGMENT FOR THE CHINESE REMAINDER THEOREM
*/

#include <stddef.h>

/* r is the number of elements in arrays m and u;
   m is the array of (pairwise relatively prime) moduli
   u is the array of coefficients
   return value is n such than n == u[k]%m[k] (k=0..r-1) and
                               n  < m[0]*m[1]*...*m[r-1]
*/
int
chinese_remainder(size_t r, int *m, int *u)
{
	size_t i;
	int modulus;
	int n;

	modulus = 1;
	for (i=0; i<r; ++i)
		modulus *= m[i];

	n = 0;
	for (i=0; i<r; ++i) {
		n += u[i] * modexp(modulus / m[i], totient(m[i]), m[i]);
		n %= modulus;
	}

	return n;
}
