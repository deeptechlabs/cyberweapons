/* file crypt.c */
/*
CA-1.0: the program
Howard Gutowitz

This version generates a random
string, encrypts it, and then decrypts it.

Please report any significant use or abuse
of this program to:
Howard Gutowitz
gutowitz@amoco.saclay.cea.fr

or

7 rue de la Clef
75005 Paris, France

or better: (after July 1993)
6395 Claremore Lane
San Diego, CA 92120


Notice: US. Patent pending on the method
embodied in this program
*/

#include "crtype.h"
#include "crutil.h"
#include "crinit.h"
#include "crperm.h"
#include "crdfus.h"
#include "crlink.h"

print_pat()

{
int i,j,k;
for (i=38; i < 76; i++)
    {
for (k=0; k < 1024; k++)
    pat2[0].m[0][k]=pat1[0].m[i][k];
for (k=0; k < 160; k++)
    pat1[0].m[i][k]='f';
for (k=160; k < 1024; k++)
    pat1[0].m[i][k]=pat2[0].m[0][k-160];
    }

for (i=114; i < 156; i++)
    {
for (k=0; k < 1024; k++)
    pat2[0].m[0][k]=pat1[0].m[i][k];
for (k=0; k < 160; k++)
    pat1[0].m[i][k]='f';
for (k=160; k < 1024; k++)
    pat1[0].m[i][k]=pat2[0].m[0][k-160];
    }

for (i=0; i < 1024; i++)
    {
for (j=0; j < 256; j++)
     printf("%c",pat1[0].m[j][(1024-1)-i]);
     printf("\n");
     }
}

do_diff()

{
int i,j;
for (i=0; i < 256; i++)
for (j=0; j < 1024; j++)
    if (pat1[0].m[i][j] != ZERO)
       {
    if (pat1[0].m[i][j] IS pat2[0].m[i][j])
       pat1[0].m[i][j]='f';
    else
       pat1[0].m[i][j]='1';
       }
}


finish_picture(pat_ptr)
pat_ptr_type pat_ptr;
{
int i,j;
for (i=147; i < 256; i++)
    {
    for (j=0; j < 1024; j++)
	{
	pat_ptr->m[i][j]='f';
	}
    }
}


decrypt_print_state(pat_ptr,iter,state)

pat_ptr_type pat_ptr;
int iter;
char state[];

{
int i;
int count;
int size,j;
count=0;
size=1024;
for (i=0; i < (iter); i++)
    {
    for (j=0; j < 5; j++)
	{
	pat_ptr->m[pat_row][count]='f';
	count++;
	}
    }

pat_ptr->m[pat_row][count-1]=ZERO;
for (i=0; i < strlen(state); i++)
    {
    if (count < size)
	if (state[i] IS ONE)
	   {
	   pat_ptr->m[pat_row][count]='1';
	   }
       else
	   {
	   pat_ptr->m[pat_row][count]='f';
	   }
    count++;
    }
pat_ptr->m[pat_row][count]=ZERO;
count++;
while (count < size)
      {
      if (count < size)
	 {
	  pat_ptr->m[pat_row][count]='f';
	 }
      count++;
     }
}

DecryptDiffusionPhase(pat_ptr,dir,current_state,link,num_its)

pat_ptr_type pat_ptr;

char dir;
char current_state[],link[];
int num_its;
{
int i;
link[0]='\0';
for (i=0; i < num_its; i++)
      {
       BuildLink(dir,current_state,link);       /* extracts a subblock of the link from current state */
       CAForward(dir,current_state);
       if (printer)
	  {
	  decrypt_print_state(pat_ptr,i,current_state);
	  pat_row++;
	  }
      }
}

Decrypt(current_state,num_its)

char current_state[];
int num_its;
{
int round;
char link[LINK_SIZE];
if (which_pat IS 0)
global_pat_ptr = &(pat1[0]);
else
global_pat_ptr = &(pat2[0]);
pat_row=0;
for (round = 0 ; round  < 2; round++)
    {

    DecryptDiffusionPhase(global_pat_ptr,'R',current_state,link,num_its);
    LinkDecryption('L',link);
    SubstitutionPhase('I',link,current_state,BLOCK_PERM_FRAME,BLOCK_NUM_PERMS,PLAIN_BLOCK_SIZE);
    Unfold('L',link,current_state);

    DecryptDiffusionPhase(global_pat_ptr,'L',current_state,link,num_its);
    LinkDecryption('R',link);
    if (round IS 0)
       {
       SubstitutionPhase('I',link,current_state,BLOCK_PERM_FRAME,BLOCK_NUM_PERMS,PLAIN_BLOCK_SIZE);
       Unfold('R',link,current_state);
       }
   }
if (printer)
finish_picture(global_pat_ptr);
}




Encrypt(current_state,num_its)

char current_state[];
int num_its;

/* main for encryption */

{

int round,i,link_size;
unsigned int size;
char link[LINK_SIZE];
for (round = 0 ; round < 2; round++)
    {
    if (round IS 0)
       {
       generate_a_rand_string(link,num_its*radius_times_2);
       }
    else
       Fold('R',current_state,link);
     if (round > 0)
    SubstitutionPhase('F',link,current_state,BLOCK_PERM_FRAME,BLOCK_NUM_PERMS,PLAIN_BLOCK_SIZE);
     LinkEncryption('R',link);
     left_subround(left_key,link,current_state,num_its,PLAIN_BLOCK_SIZE,num_its*radius_times_2);
     Fold('L',current_state,link);
     SubstitutionPhase('F',link,current_state,BLOCK_PERM_FRAME,BLOCK_NUM_PERMS,PLAIN_BLOCK_SIZE);
     LinkEncryption('L',link);
     link_size=num_its*radius_times_2;
     right_subround(right_key,link,current_state,num_its,PLAIN_BLOCK_SIZE,link_size);
     }
}




main()

{
int num_its,i,k;
unsigned int seed;


/* basic initialization */

for (i=0; i < 1; i++)
{
which_pat=i ;
initialize();
/*
printf(" enter seed \n");
scanf("%d",&seed);
srandom(seed);
*/
seed=12367;
printer=FALSE;
srandom(seed);
set_for_block();
generate_the_keys(balanced_bits,left_key,right_key);
set_for_link();
generate_the_keys(link_balanced_bits,link_left_key,link_right_key);
set_for_block();
generate_a_rand_string(plain_text,PLAIN_BLOCK_SIZE);

for (k=0; k < 30; k++) printf("%c",plain_text[k]); printf("\n");
strncpy(block_current_state,plain_text,PLAIN_BLOCK_SIZE);
num_its=NUM_ITERATIONS;
Encrypt(block_current_state,num_its);
Decrypt(block_current_state,num_its);
 printf(" size of full state after encrypt/ decrypt %d \n",strlen(block_current_state));

for (k=0; k < 30; k++) printf("%c",plain_text[k]); printf("\n");
if (strncmp(plain_text,block_current_state,PLAIN_BLOCK_SIZE) != 0)
   printf(" decryption did not invert encryption \n");
else
printf(" successful encryption/decryption of a block \n");
}


return(0);


}



