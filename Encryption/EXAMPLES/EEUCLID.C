/* I've renamed variables to coincide with Knuth tAoCP/Vol2.
		--Ken Pizzini
		ken@halcyon.com
*/
/*
  EXTENDED EUCLIDEAN ALGORITHM
*/

static void
Update(int *un, int *vn, int q)
{ 
	int tn;

	tn = *un - *vn * q;
	*un= *vn;
	*vn = tn;
}

/* return == gcd(x, n) == u*u1 + v*u2 */
int
extended_euclidian(int u, int v, int *u1_out, int *u2_out)
{
	int u1 = 1;
	int u3 = u;
	int v1 = 0;
	int v3 = v;
	int q;

	while (v3 > 0) {
		q = u3 / v3;
		Update(&u1, &v1, q);
		Update(&u3, &v3, q);
	}
	*u1_out = u1;
	*u2_out = (u3 - u1 * u) / v;
	return u3;
}
