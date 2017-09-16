/* Author: Joseph M. Reagle Jr. */

/* Purpose: Simple Program to determine letter frequency and then uses this 
 * to find the Index of Coincidence.  Right now it will only give the I.C. for  
 * lower case letters 
 */
/* The following code is provided as is.
 *        It may be copied and modified freely provided that
 *Joseph M. Reagle Jr. is acknowledged within the code as the
 *originator.
*/

/*By Joe Reagle*/
#include <stdio.h>
#include <ctype.h>
#define CONV 'a'
#define sz_M 26

float get_array(int data[sz_M][2], char *argv[])
{
   int   ch=1;
   int   counter;
   int   size=0;
   FILE  *ifp;

   printf("Frequency Distrubution\n");
   for (counter = 0; counter < sz_M; counter++) {
      data[counter][0] = CONV + counter;    /*Set up the array with letters*/
      data[counter][1] = 0;                   /*As the indicy (sp?)*/
   }
   if ((ifp=fopen (argv[1], "r"))==NULL) {
      printf("Cannot open file\n");
      exit(1);
   }
   while ( (ch=fgetc(ifp)) !=EOF) {
      if (islower(ch)) {
	 data[ch-CONV][1]++;                      /*Read in letter and store*/
	 size++;
      }
   }
   
   for (counter = 0; counter < sz_M; counter++) {
      printf("\n%c ~ %d ", data[counter][0],data[counter][1]); /*Print it out*/
   }
   printf("\n");
   printf("Size = %d", size);
   return size;
}  

void comp_ic(int data[sz_M][2], float size)
{
   float  ic=0.0;
   int    counter=0;

   for (counter = 0; counter < sz_M; counter++) {
      ic += (((data[counter][1])) * ((data[counter][1]-1)));
   }
   ic = ic/(double)((double)size*((double)size-1));
   printf("\nIC = %f\n", ic);
}


main (int argc, char* argv[])

{
   int   data[sz_M][2];
   float   size;

   size = get_array(data, argv);
   comp_ic(data, size);

}






