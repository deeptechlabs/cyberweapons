/* file crutil.c */
#include "crtype.h"
#include "crutil.h"


/* UTILITY FUNCTIONS */


extern number_to_block(x,n,block) /* makes a block of characters from a number */

int x, n;
char block[];
{
int i,j;
for (i=0; i < n; i++)
    { j= ((x >> i) & LOW_BIT_MASK); block[n-(1+i)]=ZERO +j; }
}

extern block_to_number(block,off,size) /* make a number from a block of characters */

char block[];
int off,size;
{
int i,tmp;
tmp=0;
for (i=0; i < size; i++)
    if (block[off+i] IS ONE)
	tmp+=list_of_powers_of_2[size-(i+1)];
return(tmp);
}


extern make_list_of_powers_of_2() /* make a list of the powers of 2 */

{
int i;
list_of_powers_of_2[0]=1;
for (i=1; i < 30; i++)
    list_of_powers_of_2[i]=2*list_of_powers_of_2[i-1];
}




