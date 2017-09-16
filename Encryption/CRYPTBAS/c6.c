
/* The following code is provided as is.
 *        It may be copied and modified freely provided that
 *Joseph M. Reagle Jr. is acknowledged within the code as the
 *originator.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#define HISTORY_SIZE    200
#define VOWELS_PER_LINE 200
#define STOP            -1
 
int 	heigth = 15, width = 20;			
int 	history[HISTORY_SIZE];		/* history array of past swaps*/
int 	place=0;                        /* place in history array */
char    *original_matrix;               /* oringal matrix read from file */


int is_vowel(char token)
/* is token a vowel? */
{
   switch (token) {
   case 'a':
      return 1;
   case 'e':
      return 1;
   case 'i':
      return 1;
   case 'o':
      return 1;
   case 'u':
      return 1;
   default:
      return 0;
   }
}



void get_size(char *argv[], int *size) 
/* reads in size of file */
{
   FILE    *lfp;
   int     lch;
   
   if ((lfp=fopen (argv[1], "r"))==NULL) {
      printf("Cannot open file\n");
      exit(1);
   }
   while ((lch=fgetc(lfp)) != EOF ) {
      if (lch != '\n') {
	 *size += 1;
      }
   }
   fclose (lfp);
   printf ("Size = %d\n", *size);
   return;
}




void get_matrix(char *argv[], char *matrix, int size)
/*reads in the file, same as get_size in structure*/
{
   
   FILE    *ifp;
   int     ch;
   int     counter = 0;
   
   if ((ifp=fopen (argv[1], "r"))==NULL) { /* can it be opened */
      printf("Cannot open file\n");
      exit(1);
   }
   while ((ch=fgetc(ifp)) != EOF ) {
      printf("%c", ch);
      if (ch != '\n') {
	 matrix[counter] = ch;             /* read into counter */
	 counter++;
      }
   }
   fclose(ifp);
   printf ("Read in %d chars\n", counter);
   return;
}




char get_element (char* matrix, int x, int y)
/* allows access of singular as a double array */
{
   return matrix[(y-1)*(width) + x-1];
}





void put_element (char* matrix, int x, int y, int element)
/* allows modifying a singular array as a double */
{
   matrix[(y-1)*(width) + x-1] = element;
}




void save_matrix (char *matrix, int size, FILE *fp)
/* saves the array as a rectangle of (width, height) size */
{ 
   int 		counter=0;
   
   fprintf(fp, "   %d x %d\n", width, heigth);
   fprintf(fp, "\n------------------------------\n");
   while (counter < size) {		
      fprintf(fp, "%c", matrix[counter]);
      if ( (counter+1)%width==0 ) fprintf(fp, "\n");
      counter++;
   }
   fprintf(fp, "\n------------------------------\n");
}





void print_matrix (char *matrix, int size)
/* prints the array as a rectangle of (width, height) size */
{ 
   int 	counter=1;
   int	vowels=0;
   int  array_of_vowels[VOWELS_PER_LINE]; /* history of vowel counts */
   int  AOV_counter=0;                    /* counter for above */
   int   stat_variance=0;                 /* statistical variance */
   int   stat_average =0;

   /* HEADER */
   printf("   %d x %d\n", width, heigth);
   printf("------------------------------\n");
   while(counter<=width)
      printf(" %d", counter++%10);	/* head of columns    */
   printf("\n");

   /* PRINT AND UPDATE STAT INFO */
   counter=0;
   while (counter < size) {		
      printf(" %c", matrix[counter]);   /* print the value   */
      if (is_vowel(matrix[counter])){   		
	 vowels++;			/* a vowel was found */	 
      }
      if ( (counter+1)%width==0 ) {
	 printf("  %d\n", vowels);	/* go to next row    */
	 array_of_vowels[AOV_counter] = vowels;
	 AOV_counter++;
	 vowels = 0;
      }
      counter++;
   }
   if (size%width != 0) {         /* last line of vowel output */
      printf("  %d\n", vowels);   /* if it was a perfect fit, don't bother*/
      array_of_vowels[AOV_counter] = vowels;
      AOV_counter++;
      vowels = 0;
   }
   array_of_vowels[AOV_counter] = STOP;   /* signifies end */

   /* FOOTER */
   counter=1;                           
   while(counter<=width)
      printf(" %d", counter++%10);	/* foot of columns    */	       
   printf("\n------------------------------\n");
   
   /* COMPUTE STATISTICS */
   AOV_counter = 0;
   while (array_of_vowels[AOV_counter] != STOP) {  /* compute stat_aver */
      stat_average += array_of_vowels[AOV_counter]; /* sum the elements  */
      AOV_counter++;
   }
   stat_average = stat_average/AOV_counter;        /* average the elemts */
   AOV_counter = 0;
   while (array_of_vowels[AOV_counter] != STOP) {  /* compute variance  */
      stat_variance += pow( (array_of_vowels[AOV_counter] - stat_average), 2);
      AOV_counter++;
   }	    
   printf("The Statistical Average is %d\n", stat_average);
   printf("The Statistical Variance is %d\n", stat_variance);
}





void swap(char *matrix, int first, int second)
/* does a permutation of columns */
{
   int						temp;
   int						row=1;
   
   history[place] = first;		/* update this history file     */
   place=(place+1)%HISTORY_SIZE;	/* with the two columns swapped */
   history[place]= second;
   place=(place+1)%HISTORY_SIZE;	
   printf("history for %d and %d recorded\n", 
	  history[place-2], history[place-1]);
   while (row <= heigth) {    
      temp = get_element(matrix, first, row);
      put_element(matrix, first, row, get_element(matrix, second, row));
      put_element(matrix, second, row, temp);		
      row++;		       /* swaps elements of comns. 1 row at a time */
   }
}





void undo(char *matrix)
/* swap the last 2 columns in the history array */
{
   if (place < 2)  
      printf("Error:Undo--Empty history file (At original)\n");
   else {
      printf("Swapping %d and %d back\n", 
	     history[place-1], history[place-2]);	
      swap (matrix, history[place-1], history[place-2]);
      place -= 4;      /* since undo, causes the undo swap to be entered */
   }		       /* into the history, I must go back 4 spaces in it*/
}




void resize(int x, int y)
/* resize the rectangle */
{
   width  = x;
   heigth = y;
}




void advise(int size)
/* advise for column size */
{
   int root;			     /* sqrt of size */
   int row;			     /* for any given row */
   int column;			     /* for any given column */
   int high, low; 		     /* low and high bound for coumn */
   
   root = ceil(sqrt(size));          /* defines high range*/
   row = root;
   printf("The root of size %d is =~ %d\n", size, root);
   while (row >= ceil(root/2)) {     /* defines low range */
      printf("row = %d,  c =", row);
      high = floor(size/(row-1));
      low  = ceil((float)size/row); 
      for (column=low;column<=high;column++) {
	 printf(" %d", column);      /* it works according to kinkov */
	 if(column*row==size) printf("*"); /* yields an even rectangle */
      }
      row--;
      printf("\n");
   }
}




void interface(char* argv[], char *matrix, int size, FILE *fp)
/* a clumsy interface to my routines */
{
   char str[10];
   int  option1, option2;
   
   while (str[0]!='e') {
      printf("command: ");
      gets(str);
      printf("command registered\n");
      switch (str[0]) {
      case 'a':                 /* advise */
	 advise(size);
	 break;
      case 'h':                 /* help */
	 printf("Advise, Exit, New, Print, Resize, SAve, SWap, Undo\n");
	 break;
      case 'e':                 /* exit */
	 printf("Exiting\n");
	 break;
      case 'r':   		/* resize */	
	 sscanf(str, "%*s %d %d", &option1, &option2);
	 width = option1;
	 heigth = option2;
	 print_matrix(matrix, size);	
	 break;
      case 's': 			
	 if (str[1]=='w') {	/* swap */ 		
	    sscanf(str, "%*s %d %d\n", &option1, &option2);
	    printf ("o1 = %d, o2 = %d\n", option1, option2);
	    swap(matrix, option1, option2);
	    print_matrix(matrix, size);	
	 }
	 else if (str[1]=='a') {/* save */
	    save_matrix(matrix, size, fp);
	    printf("Saved message\n");
	 }
	 else printf("Error in command: swap or save?\n");
	 break;
      case 'u': 		/* undo */
	 undo(matrix);
	 print_matrix(matrix, size);	
	 break;
      case 'n':			/* new */
	 place=0;		/* reset history */
	 strcpy(matrix, original_matrix);       /* restores matrix */
	 print_matrix(matrix, size);	
	 break;
      case 'p':			/* print */
	 print_matrix(matrix, size);	
	 break;
      default:
	 printf("Error, didn't understand command\n");		
      }		
   }
}




main (int argc, char* argv[])
{
   
   int     size = 0;
   char    *matrix;
   FILE	*fp;
   
   if(!(fp=fopen("crypt.log", "w"))) {   /* log file */
      printf("cannot open file\n");
      exit(EXIT_FAILURE);
   }	 
   get_size(argv, &size);
   if (!(matrix = malloc(size))) printf("Error\n");
   if (!(original_matrix = malloc(size))) printf("Error\n");
   get_matrix(argv, original_matrix, size);
   strcpy(matrix, original_matrix);
   print_matrix(matrix, size);
   print_matrix(original_matrix, size);
   advise(size);
   interface(argv, matrix, size, fp);	
   fclose(fp);                           /* close log file */
   return EXIT_SUCCESS;
}








