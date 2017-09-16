/* file crdfus.c */
#include "crtype.h"
#include "crutil.h"
#include "crdfus.h"
#include "crlink.h"




/* ENCRYPTION FUNCTION AND SUB-FUNCTIONS */

/* the next four functions represent the basic instructions
   each processor must perform */

extern char right_access_key(r_key,bit,number)


/* function to access right CA rule depending on
   a bit and a number which together form the
   index into the rule table */
char r_key[];
char bit;
int number;

{
if (bit IS ZERO)
    return(r_key[2*number]);
else
    return(r_key[2*number+1]);
}

extern char left_access_key(l_key,bit,number)

char l_key[];
char bit;
int number;

{
if (bit IS ZERO)
    return(l_key[number]);
else
    return(l_key[number+number_of_partial_neighborhoods]);
}


extern set_high_bit(bit,number) /* set high bit of number
			    depending on the character bit */

char bit;
int *number;


{
   if (bit IS ONE)
      (*number)=(*number) | high_bit_mask;
}


extern set_low_bit(bit,number) /* set low bit of number
			    depending on the character bit */

char bit;
int *number;


{
   if (bit IS ONE)
      (*number)=(*number) | LOW_BIT_MASK;
}


extern right_shift(number) /* shift number right one place */

int *number;
{
(*number)=((*number) >> 1);
}


extern left_shift(number) /* shift number left one place */

int *number;
{
(*number)=((*number) << 1);
if ((*number) > encrypt_bit_cut_off)
   (*number)=((*number) ^ number_of_partial_neighborhoods);


}


extern Update(direction,the_key,current_state,state_place,ball_point)

/* updates the state of a site in the array current_state */

char direction;

char the_key[],current_state[];

int state_place,*ball_point;
{

if (direction IS 'R')
   {
   current_state[state_place]=right_access_key(the_key,current_state[state_place],*ball_point);
   left_shift(ball_point);
   set_low_bit(current_state[state_place],ball_point);
   }
else
   {
   current_state[state_place]=left_access_key(the_key,current_state[state_place],*ball_point);
   right_shift(ball_point);
   set_high_bit(current_state[state_place],ball_point);
   }
}





shove_right(shove,local_link,current_state)  /* move it over */

int shove;
char local_link[],current_state[];

{
char tmp_state[BLOCK_SIZE];
int i,size;
if (radius IS 3) size=LINK_BLOCK_SIZE;
else size=PLAIN_BLOCK_SIZE;
strncpy(tmp_state,current_state,size);
for (i=0; i < size; i++)
    current_state[i+shove]=tmp_state[i];
for (i=0; i < shove; i++)
    current_state[i]=local_link[i];
if ((shove+size) < PLAIN_BLOCK_SIZE)
current_state[shove+size]='\0';
}




extern right_subround(r_key,local_link,current_state,num_its,in_state_size,link_size)
/* applies the irreversible CA num_its times to in_state to
get out_state, driven by information in link */

char r_key[],local_link[],current_state[];
int num_its;
int in_state_size,link_size;


{
int state_place;
int i,k,ball_point;
current_state_size=in_state_size;
shove_right(link_size,local_link,current_state);  /* move state over  */
for (k=0; k < num_its; k++)
    {
    right_place_link(current_state,
    link_size-((k+1)*radius_times_2),&ball_point);
    state_place=link_size-(k*radius_times_2);
    for(i=0; i< in_state_size+(k*radius_times_2); i++)
       {
       Update('R',r_key,current_state,state_place,&ball_point);
       state_place++;
       }
    }

}


extern left_subround(l_key,local_link,current_state,num_its,in_state_size,link_size)
/* applies the irreversible CA num_its times to in_state to
get out_state, driven by information in link */

char l_key[];
char local_link[],current_state[];
int num_its;
int in_state_size,link_size;


{
int state_place;
int i,k,ball_point;
if (radius IS 3) current_state[LINK_BLOCK_SIZE]='\0';
else current_state[PLAIN_BLOCK_SIZE]='\0';
current_state_size=in_state_size;

for (k=0; k < num_its; k++)
    {
    left_place_link(local_link,current_state,
    link_size-((k+1)*radius_times_2),&ball_point);
    state_place=current_state_size-neighborhood_size;
    for(i=0; i< (current_state_size-radius_times_2); i++)
       {
       Update('L',l_key,current_state,state_place,&ball_point);
       state_place--;
       }
    }
}




extern CAForward(direction,current_state)

char direction,current_state[];

{

int i,j,indx;
int begin_place;
int state_size;


state_size=strlen(current_state);
if (radius IS 5)
{
if (direction IS 'L') key = &(left_key[0]);
else
key = &(right_key[0]);
}

if (radius IS 3)
{
if (direction IS 'L') key = &(link_left_key[0]);
else
key = &(link_right_key[0]);
}

begin_place= state_size-(neighborhood_size);

indx=block_to_number(current_state,begin_place, neighborhood_size);
j=0;
for (i= begin_place ; i >=0;  i--)
    {
    /* lookup the state for position i in current_state */
    current_state[i]=(*(key+indx));
    right_shift(&indx);
    j++ ;
    if (current_state[begin_place-j] IS ONE)
       indx=indx | neighborhood_mask;
    }

/* array is now shorter */
current_state[state_size-radius_times_2]='\0';
state_size-=radius_times_2;
}



extern BuildLink(direction,current_state,local_link)

char direction,current_state[],local_link[];
{

int i,cur_size,link_size;
link_size=strlen(local_link);

if (direction IS 'L')
   {
   cur_size=strlen(current_state);
   for (i=0; i < radius_times_2; i++)
       local_link[link_size+i]=current_state[i+cur_size-radius_times_2];
   }
else
   {
   for (i=0; i < radius_times_2; i++)
       local_link[link_size+i]=current_state[i];
   }
if ((link_size+radius_times_2) < LINK_SIZE)
local_link[link_size+radius_times_2]='\0';
}





