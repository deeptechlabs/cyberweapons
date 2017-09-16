/* Misnamed cross-refernce; this is modular exponentiation.
   (Old cross-reference text kept for reference purposes.)
		--Ken Pizzini
		ken@halcyon.com
*/
/*
  MODULAR MULTIPLICATION
*/

int
modexp(int a, int x, int n)
{
	int r = 1;

	while (x > 0){
		if (x % 2 == 1)	/* is x odd? */
			r = (r * a) % n;
		a = (a*a) % n;
		x /= 2;
	}
	return r;
}
