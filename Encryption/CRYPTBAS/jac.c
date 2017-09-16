/* Author: Joseph M. Reagle Jr.
 * Purpose: To use the Jacobi function to find the probably prime numbers 
 * within a certain numberic range.  The data types can prove to be problematic
 * for large numbers.
 */
/* The following code is provided as is.
 *        It may be copied and modified freely provided that
 *Joseph M. Reagle Jr. is acknowledged within the code as the
 *originator.
*/


#include<stdio.h>
#include<stdlib.h>
#include<math.h>
#define TRUE 1
#define FALSE 0

double mod(double a, double n)
   /* my own double mod function because the numbers exceed the size of
      long int, and could conceiveable exceed the unsigned long int in
      c, which is about 4 million */
{
   double fp = 0;
   double wp = 0;
   double result = 0;

   if (a/n < 1)     /* if the result is a fraction, then there is only a */
      return a;     /* remainder */
   else {
      fp = modf(a/n, &wp);
      result = a - (wp * n);
      return result;
   }
}

int gcd(double y, double z)
   /* finds a greatest common divisor, Denning's method */
{
   double a, b, c;
   a = y;
   b = z;
   c = 1;
   
   while (b != 0) {
      c = mod(a,b);
      a = b;
      b = c;
   }
   return (int)a;
}


long int fastexp(double a, double z, double n)
   /* Denning's method of fastexp */
{
   double a1 = a;
   int z1 = (int)z;
   double x = 1;

   while (z1 != 0) {
      while (z1%2==0) {
	 z1 = z1/2;
	 a1 = mod(a1*a1,n);
      }
      z1--;
      x = mod(x*a1,n);
   }
    return (long int)x;
}

long int j(long int a, long int b) 
   /* evaluates (a/b) according to Denning's algorithm */
{
   if (a==1) {
      return 1.0;
   }
   else {
      if (a%2 == 0) {
	 if( ((b*b-1)/8)%2 == 0 )
	    return j(a/2,b);	 
	 else 
	    return -(j(a/2,b));
      }
      else {
	 if ( ((a-1)*(b-1)/4)%2 == 0) 
	    return j(b%a,a);
	 else 
	    return -(j(b%a,a));
      }
   }
}

main ()
   /* I just realized that this program finds things in the range of hundreds
      thousands, I originally had it working for 7,500,000 to 7,510,000.  So 
      it should work for even much bigger numbers.   (As long as the size of 
      a number squared does not overflow a double.) */

{
   long int a = 2;
   int  counter = 0;
   int  b = 750001;
   long int z = 0;
   long int jac = 0;
   long int  exp = 0;
   int prime = TRUE;

   printf("The following are prime:\n");
   while(b <= 751000) {
      a = 2;
      prime = TRUE;
      while(a<=20) {
	 if (gcd(a,b) == 1) {
	    jac = j((long int)a,(long int)b);
	    jac = (jac + b)%b;
	    exp = fastexp(a,(b-1)/2, b);

	    if (jac != exp)
	       prime = FALSE;
	 } 
	 a++;
      }
      if (prime)
	 printf("%d\n", b);
      b += 2;
   }
}

       

      
	       
	 














