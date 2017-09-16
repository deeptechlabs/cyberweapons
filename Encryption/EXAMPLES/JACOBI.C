/* Added cases (0) and (5') based on Knuth;
   don't see how to apply (2) without a factoring primitive
   (factor2() is my stub for this);
   because of (5'), I'm not sure that (5) is appropriate.
		--Ken Pizzini
		ken@halcyon.com
*/
/*
  This algorithm computes the Jacobi symbol recursively:
*/

int
jacobi(int a, int b)
{
	int a1, a2;

	if (a >= b)			/* 4 */
		a %= b;
	if (a == 0)			/* 0 */
		return 0;
	if (a == 1)			/* 1 */
		return 1;
	if (a == 2)			/* 3 */
		if (((b*b-1) / 8) % 2 == 0)
			return 1;
		else
			return -1;

	/* 5' */
	if (a & b & 1)	/* both a and b are odd */
		if (((a-1)*(b-1)/4) % 2 == 0)
			return +jacobi(b, a);
		else
			return -jacobi(b, a);
	/* 5 */
/* is the if-case correct?  If so remove these comment markers...
	if (gcd(a, b) == 1)
		if (((a-1)*(b-1)/4) % 2 == 0)
			return +jacobi(b, a);
		else
			return -jacobi(b, a);
*/

	/* 2 */
	factor2(a, &a1, &a2);
	return jacobi(a1, b) * jacobi(a2, b);
}
