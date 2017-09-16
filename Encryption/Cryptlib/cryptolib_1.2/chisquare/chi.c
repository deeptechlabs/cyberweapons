/*
 *	Chi-Square Cumulative Distribution
 */
#include "bash.h"

#define TWOPI 6.2831853071795864769252864
extern double erf(), gamma(), exp(), sqrt(), log(), pow();

double
nCHI(x, n)
double x;
int n;
{
	double nu;
	double y;

	nu = (double)n;
	y = (pow(x/nu, 1.0/3.0) - (1.0 - 2.0/(9.0*nu)))
		/ sqrt(2.0/(9.0*nu));
	y = (1.0 + erf(y/sqrt(2.0))) * 0.5;
	return y;
}

double
CHI(x, n)
double x;
int n;
{
	double nu;
	double y;

	nu = (double)n;
	if (n > 50)
		return nCHI(x, n);
	if (x > 100.0)
		return 1.0;
	if (n == 1) {
		y = erf(sqrt(0.5*x));
		return y;
	}
	if (n == 2) {
		y = 1.0 - exp(-0.5*x);
		return y;
	}
	y = CHI(x, n - 2)
	 - exp(0.5*(nu - 2.0)*log(0.5*x) - 0.5*x - gamma(0.5*nu));
	return y;
}

double
chi(x, n)
double x;
int n;
{

	return CHI(x, n);
}


/*
main()
{
	double x;
	int n;

	scanf("%lf%d", &x, &n);
	printf("%f\n", CHI(x, n));
}
*/
