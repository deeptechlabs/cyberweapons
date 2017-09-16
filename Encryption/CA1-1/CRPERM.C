/* file crperm.c contains the permutation (reversible CA) stuff */

#include "crtype.h"
#include "crutil.h"
#include "crperm.h"


perm_print_state(pat_ptr,state)

pat_ptr_type pat_ptr;
char state[];

{
int i,j;
int count;
int size;
count=0;
size=1024;
for (i=0; i < 31; i++)
    {
  /*  printf("fffff"); */
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
	  /* printf("%c",ZERO); */
	   pat_ptr->m[pat_row][count]='1';
	   }
       else
	   {
	  /* printf("%c",'f'); */
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
	 /* printf("f"); */
	  pat_ptr->m[pat_row][count]='f';
	 }
      count++;
     }
/* printf("\n"); */
}

extern invert_perm(perm,num_el)

int perm[],num_el;

/* inverts a permutation */
{
int inv_perm[PERM_SIZE];
int i;
for (i=0; i < num_el; i++)
inv_perm[perm[i]]=i;
for (i=0; i < num_el; i++)
perm[i]=inv_perm[i];
}



extern basic_apply_permutation(perm,current_state,state_size,el_size,off_set)

/* applies a permutation to a state */

int perm[];                                /* the permutation                */
char current_state[];
int state_size,el_size,off_set;                       /* perm block size, reading frame */


{
int i,place;
char block[16],b2[16];
int num,k,hits;
place=off_set;
if ((state_size % el_size) !=0 )
printf(" state_size %d is not divisible by el_size %d \n");
hits = ((int) state_size/el_size);
      for (k=0; k < hits; k++)
      {
      if (k IS (hits-1))
	 {
	 for (i=0; i < el_size ; i++) b2[i]=current_state[(place+i) % state_size];
	     num=block_to_number(b2,0,el_size);
	 }
      else
      num=block_to_number(current_state,place,el_size);
      number_to_block(perm[num],el_size,block);  /* should be done by a lookup */
      if (k IS (hits-1))
	 for (i=0; i < el_size; i++)
	      current_state[((place+i) % state_size)]=block[i]; /* periodic boundary */
      else
	 for (i=0; i < el_size; i++)
	      current_state[place+i]=block[i];

      place+=el_size;
      }
}



extern apply_permutation(direction,perm,current_state,state_size,el_size)

char direction;
int perm[];                                /* the permutation       */
char current_state[];                           /* the state applied to  */
int state_size,el_size;                    /* state,perm block size */
{
int i;

for (i=0; i < el_size; i++)
    if (direction IS 'F')
       {
      /* printf(" forward \n"); */
       basic_apply_permutation(perm,current_state,state_size,el_size,i);
       }
    else
       {
      /*  printf(" backward \n"); */
       basic_apply_permutation(perm,current_state,state_size,el_size,el_size-(1+i));
       if (printer AND (state_size IS PLAIN_BLOCK_SIZE))
	   {
	   perm_print_state(global_pat_ptr,current_state);
	   pat_row++;
	   }
       }
}



extern SubstitutionPhase(direction,local_link,current_state,el_size,num_el,state_size)

char direction;
char local_link[],current_state[];
int el_size,num_el,state_size;

{
int perm[PERM_SIZE];
int num_bits;
btree_build(el_size);
tree_to_perm(local_link,num_el,perm,&num_bits);
if (direction IS 'I')
{
invert_perm(perm,num_el);
}
apply_permutation(direction,perm,current_state,state_size,el_size);
}





extern btree_recursive_type_node(bnode_ptr)

bnode_ptr_type bnode_ptr;

{
printf(" level,leaf,num,following: %d %d  %d %d \n",
bnode_ptr->level,bnode_ptr->leaf, bnode_ptr->num,bnode_ptr->following); if (bnode_ptr->leaf >0 ) {
   if ((bnode_ptr->leaf IS 1) OR (bnode_ptr->leaf IS 3))
      {
      /*  printf(" decending from level %d to follow left  \n", bnode_ptr->level); */
       if (bnode_ptr->next[0] IS NULL)
	  printf(" left pointer is null \n");
       else
	  btree_recursive_type_node(bnode_ptr->next[0]);
      }
   if ((bnode_ptr->leaf IS 2) OR (bnode_ptr->leaf IS 3))
      {
      /* printf(" decending from level %d to follow right \n", bnode_ptr->level); */
       if (bnode_ptr->next[1] IS NULL)
	  printf(" right pointer is null \n");
       else
	  btree_recursive_type_node(bnode_ptr->next[1]);

      }
   }

}



extern btree_type_node(bnode_ptr)

bnode_ptr_type bnode_ptr;

{
printf(" level,leaf,num: %d %d  %d \n",bnode_ptr->level,bnode_ptr->leaf,
bnode_ptr->num);

}




extern btree_assign_next_pointers(bnode_ptr)

bnode_ptr_type bnode_ptr;

{

int i,j;
for (i=0; i < 2; i++)
    {
    btree_node_counter++;
    if (btree_node_counter IS  MAX_B_NODES) printf(" NEED MORE NODES!!!\n");
    bnode_ptr->next[i]= (&btree[btree_node_counter]);
    bnode_ptr->next[i]->mother=(bnode_ptr);
    for (j=0; j < 2; j++)
    bnode_ptr->next[i]->next[j]= (bnode_ptr_type) NULL;
    }
}




extern btree_do_division(bnode_ptr,block_size)

bnode_ptr_type bnode_ptr;
int block_size;


{
 int i;
 bnode_ptr_type next_bnode_ptr;
 if (bnode_ptr->level < block_size)
    {
    for (i=0;  i < 2; i++)
	{
	next_bnode_ptr =bnode_ptr->next[i];
	next_bnode_ptr->level=(bnode_ptr->level)+1;
	next_bnode_ptr->leaf=3;
	next_bnode_ptr->num=-1;
	btree_assign_next_pointers(next_bnode_ptr);
	btree_do_division(next_bnode_ptr,block_size);
	}
    }

else if (bnode_ptr->level IS block_size) /* its a leaf */
     {
     bnode_ptr->leaf=0;
     bnode_ptr->num=btree_perm_num;
     btree_perm_num++;
     }

else printf(" bad branch in btree_do_division \n");

}



extern btree_make_root(root_ptr,block_size)

bnode_ptr_type root_ptr;
int block_size;

{
root_ptr->level=0;
root_ptr->leaf=3;
root_ptr->num=-1;
root_ptr->mother=NULL;
btree_assign_next_pointers(root_ptr);
btree_do_division(root_ptr,block_size);
}


extern tell_the_news(bnode_ptr)

bnode_ptr_type bnode_ptr;
{
bnode_ptr_type mother_ptr;

   mother_ptr=bnode_ptr->mother;

if (mother_ptr != NULL)
      {
      if ((mother_ptr->leaf) IS 3)
	 {
	 if (mother_ptr->following  IS 0) /* last followed to left */
		 mother_ptr->leaf=2;
	 else if (mother_ptr->following  IS 1) /* last followed to right */
		 mother_ptr->leaf=1;
	 else
	    printf(" don't know what followed last %d \n",mother_ptr->following);
	 }
     else {
	  tell_the_news(mother_ptr);
	  }
      }
}

extern int   btree_read(local_link,where,bnode_ptr,return_num)

char local_link[];
int *where;
bnode_ptr_type bnode_ptr;
int *return_num;

{
char which;
if (bnode_ptr->leaf IS 0) /* got to leaf */
   {
   tell_the_news(bnode_ptr);
   (*return_num)=bnode_ptr->num;
   }
else if (bnode_ptr->leaf IS 1) /* skip down */
   {
   bnode_ptr->following=0;
   btree_read(local_link,where,bnode_ptr->next[0],return_num);
   }
else if (bnode_ptr->leaf IS 2) /* skip down */
   {
   (bnode_ptr->following)=1;
   btree_read(local_link,where,bnode_ptr->next[1],return_num);
   }
else if (bnode_ptr->leaf IS 3) /* split */
   {
  /*  printf(" splitting with %d \n",*where); */
   which=local_link[(*where)];
/* printf(" where %d which is %c \n",*where,which); */
   (*where)++;

   if (which IS ZERO)
      {
      bnode_ptr->following=0;
      btree_read(local_link,where,bnode_ptr->next[0],return_num);
      }
   else if (which IS ONE)
      {
      bnode_ptr->following=1;
      btree_read(local_link,where,bnode_ptr->next[1],return_num);
      }
   else printf(" dont know which %c \n",which);
   }
}



extern tree_to_perm(local_link,num_el,perm,count)

char local_link[];
int num_el;
int perm[];
int *count;

  {
  int where;
  int i;
  bnode_ptr_type bnode_ptr;
  where=0;
  for (i=0; i < num_el; i++)
      {
      bnode_ptr=(&btree[0]);
      btree_read(local_link,&where,bnode_ptr,&perm[i]);
	/* printf(" i %d, permutation[i] %d where %d \n",i,perm[i],where);  */
      }
/* printf(" final number of bits used %d \n",where);  */
(*count)=where;

/* printf(" so finally, the permutation  \n");
  for (i=0; i < num_el; i++)
      printf(" i %d perm[i] %d \n",i,perm[i]);
*/
  }



extern btree_build(block_size)

int block_size;
{
  btree_perm_num=0;
  btree_node_counter=0;
  btree_make_root(&btree[0],block_size);

}






