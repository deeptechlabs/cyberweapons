/* Double check the formulas;
   I may have interpreted the pseudo-code incorrectly.
		--Ken Pizzini
		ken@halcyon.com
*/
/*
  The algorithm to recover x0 from xt is as follows:
*/

int
x0(int p, int q, int n, int xt)
{
	int a, b, u, v, w, z;

	/* we already know that gcd(p, q) == 1 */
	(void)extended_euclidian(p, q, &a, &b);
	u = ((p+1)/4)*xt % (p-1);
	v = ((q+1)/4)*xt % (q-1);
	w = xt*u % p;
	z = (xt % q)*v % q;
	return (b*q*w + a*p*z) % n;
}
