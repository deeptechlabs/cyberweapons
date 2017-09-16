/* removed the restriction on x, y:
    gcd(x, y) == gcd(y, x)
    gcd(x, y) == gcd(-x, y)
    gcd(x, 0) == abs(x)
		--Ken Pizzini
		ken@halcyon.com
*/
/*
  returns GCD of x an y, assuming both x and y are greater than 0
*/

int
gcd(int x, int y)
{
	int g;

	if (x < 0)
		x = -x;
	if (y < 0)
		y = -y;
	g = y;
	while (x > 0) {
		g = x;
		x = y % x;
		y = g;
	}
	return g;
}
