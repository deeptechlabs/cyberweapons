/* Author: Joseph M. Reagle Jr.
 * Purpose: To determine the percentage of relatively prime numbers.
 */
/* The following code is provided as is.
 *        It may be copied and modified freely provided that
 *Joseph M. Reagle Jr. is acknowledged within the code as the
 *originator.
*/


#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#define MAX_NUM 200000

int gcd(int y, int z)
{
   int a, b, c;
   a = y;
   b = z;
   c = 1;

   while (b != 0) {
      c = a%b;
      a = b;
      b = c;
   }
   return a;
}

void main()
{
   int    one, two;
   double match;                   /* Amount of numbers with gcd==1 */
   double total;                   /* Total number of compares done */
   int    counter = 0;             /* How many interations       */
   srand(3);

   while (counter < MAX_NUM ) {
      one = rand();
      two = rand();
      if ( gcd(one, two) == 1 ) { /* Are they relatively prime?*/
	 match++;                 /* If they are, record it    */
      }
      total++;        
      counter++;
   }
   printf ("Percent is equal to =%f\n", match/total*100);
}
}
