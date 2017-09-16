/* Author: Joseph M. Reagle Jr.
 * Purpose: To exhaustively break knapsack ciphers.
 */
/* The following code is provided as is.
 *        It may be copied and modified freely provided that
 *Joseph M. Reagle Jr. is acknowledged within the code as the
 *originator.
*/

#include <math.h>
#include <stdio.h>
#define TRUE = 1
#define FALSE =0;

int summation(int sack[], int a[])
   /* gives the summation of the knapsack and binary vectors */
{
   int counter=0;
   int sum=0;

   while (counter < 16) {
      sum = sum + a[counter]*sack[counter];
      counter++;
   }
   return sum;
}

void update(int a[])
   /* increment the binary vector a[] by 1 */
{

   int counter=0;
   int not_done=1;
   
   while(not_done && counter < 16) {
      if (a[counter] == 1) {
	 a[counter] = 0;
	 counter++;
      }
      else {
	 a[counter] = 1;
	 not_done=0;
      }
   }
}
      
void binary (int a[])
   /* print the binary vectore a[] */
{
   int counter=0;

   while (counter < 16) {
      printf("%d", a[counter]);
      if (counter == 7 )
	 printf (" ");
      counter++;
   }
   printf("\n");
}

void text (int a[])
/* print the text */
{
   double ascii = 0.0;
   double power = 0.0;
   int counter = 8;

   while (counter < 16) {
      ascii += a[counter] * pow(2,power);
      counter++;
      power = power + 1;
   }
   printf("%c", (int)ascii);

   
   power = 0.0;
   ascii = 0;
   counter = 0;

   while (counter < 8) {
      ascii += a[counter] * pow(2,power);
      counter++;
      power = power + 1;
   }
   printf("%c", (int)ascii);
}
    
main (int argc, char* argv[])
{
   int  x = 0;
   int  sack[16] = {16477,32954,39085,18393,42917,9580,2683,34105,41387,
		      12651,41779,13435,37600,5077,26631,5747};
		       /* The given numbers of the knap sack */
   int  a[16] = { 1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
   FILE *ifp;
   int  not_found = 1;
   int  counter=0;
   int  number=0;

   if ((ifp=fopen (argv[1], "r"))==NULL) {
     printf("Cannot open file\n");
     exit(1);
   }

   while (fscanf(ifp, "%d", &x) != EOF ) {
      if (x == -1)
	 printf("\n");
      else {
	 while (summation(sack, a) != x) { /* find the bit vector */

	    update(a);
	    number++;
	 }
	 counter = 0;
	 binary(a);                        /* print the bit vector */
	 while (counter < 16) {
	    if (a[counter] == 1)
	       printf ("%d ", sack[counter]);
	    counter++;
	 }
	 printf("\n");
	 text(a);                         /* print 2 chars of the bit vector */
      }     
   }
}








