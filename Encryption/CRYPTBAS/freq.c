/*Simple Program to determine letter frequency within a text file*/
/*which is passed as an argument.*/

/*By Joe Reagle*/

/* The following code is provided as is.
 *        It may be copied and modified freely provided that
 *Joseph M. Reagle Jr. is acknowledged within the code as the
 *originator.
*/


/*Maybe I could get this to compare these frequencies against the*/
/*standard frequencies and give 2 or 3 gueses as plain text      */
/*correspondance.*/

#include <stdio.h>
#define sz_M 100

main (int argc, char* argv[])

{
   int  ch=1;
   int   counter;
   int   data[sz_M][2];
   FILE  *ifp;

   printf("toden = %d", ' ');
   for (counter = 0; counter < sz_M; counter++) {
      data[counter][0] = ' ' + counter;       /*Set up the array with letters*/
      data[counter][1] = 0;                   /*As the indicy (sp?)*/
   }
   if ((ifp=fopen (argv[1], "r"))==NULL) {
      printf("Cannot open file\n");
      exit(1);
   }
   while ( (ch=fgetc(ifp)) !=EOF) {
      data[ch-' '][1]++;                      /*Read in letter and store*/
   }

   for (counter = 0; counter < sz_M; counter++) {
      printf("%c ~ %d \n", data[counter][0],data[counter][1]); /*Print it out*/
   }
   printf("\n");
}
}
