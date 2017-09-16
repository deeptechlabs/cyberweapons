/* file crlink.c  link treatment */
#include "crtype.h"
#include "crutil.h"
#include "crperm.h"
#include "crlink.h"
#include "crdfus.h"




extern LinkEncryption(direction,current_state)

char direction;
char current_state[];

{


int i;
char link_link[LINK_LINK_SIZE+1];
char link_block[BLOCK_SIZE];
set_for_link();

/* the current_state is broken into two parts
a state and a link for the link */
   for (i=0; i < LINK_LINK_SIZE; i++)
       link_link[i]=current_state[(LINK_SIZE-1)-i];
for (i=0; i < LINK_BLOCK_SIZE; i++) link_block[i]=current_state[i];
   SubstitutionPhase('F',link_link,link_block, LINK_PERM_FRAME,LINK_NUM_PERMS,LINK_BLOCK_SIZE);
if (direction IS 'L')
   left_subround(link_left_key,link_link,link_block, NUM_ITERATIONS,LINK_BLOCK_SIZE,LINK_LINK_SIZE);
else
   right_subround(link_right_key,link_link,link_block,NUM_ITERATIONS,LINK_BLOCK_SIZE,LINK_LINK_SIZE);
set_for_block();
link_block[LINK_SIZE]='\0';
strncpy(current_state,link_block,LINK_SIZE);
}




undo_subround(direction,local_link,current_state,num_its)

char direction,local_link[],current_state[];
int num_its;

{
int i;
for (i=0; i < num_its; i++)
      {
      BuildLink(direction,current_state,local_link);
      CAForward(direction,current_state);
      }
}





extern LinkDecryption(direction,current_state)

char direction;

char current_state[];

{


char link_link[LINK_LINK_SIZE];
link_link[0]='\0';
set_for_link();    /* set radius dependent parameters for link */
undo_subround(direction,link_link,current_state,NUM_ITERATIONS);
SubstitutionPhase('I',link_link,current_state,
   LINK_PERM_FRAME,LINK_NUM_PERMS,LINK_BLOCK_SIZE);
UnfoldLink(link_link,current_state);
set_for_block();   /* set radius dependent parameters for block */
}






extern right_place_link(current_state,link_place,ball_point)

/* returns number representing the link to
get the ball rolling on encryption iteration */

char current_state[];
int link_place,*ball_point;



{
(*ball_point)=block_to_number(current_state,link_place,
radius_times_2);
}


extern left_place_link(local_link,current_state,link_place,ball_point)

/* places 2*radius worth of
link at the right end of current_state.
also returns number representing the link to
get the ball rolling on encryption iteration */

char local_link[],current_state[];
int link_place,*ball_point;



{

int i;
current_state_size =strlen(current_state);
for (i=0; i < radius_times_2; i++)
    current_state[current_state_size+i]=local_link[i+link_place];
(*ball_point)=block_to_number(current_state,current_state_size,
radius_times_2);
current_state_size+=radius_times_2;
current_state[current_state_size]='\0';
}




extern Fold(direction,text,local_link)                     /* depending on directionection
						of last subround, skims
						off a link*/
char direction,text[],local_link[];

{
int i,off_set;

if (direction IS 'L')  /* skim left */
   off_set=PLAIN_BLOCK_SIZE;
else
   off_set=0;                 /* skim right */

   for (i=0; i < LINK_SIZE; i++)
       local_link[i]=text[off_set+i];


if (direction IS 'R')  /* skimed on left */
   for (i=0; i < PLAIN_BLOCK_SIZE; i++)
   text[i]=text[i+LINK_SIZE];


}

extern Unfold(direction,local_link,state)  /*put link on left */

char direction,local_link[],state[];

{
int i,size;
char tmp_state[BLOCK_SIZE];
if (direction IS 'R')
   {
size=strlen(state);
strcpy(tmp_state,state);

strcpy(state,local_link);
for (i=0; i < size; i++)
    state[i+LINK_SIZE]=tmp_state[i];
state[LINK_SIZE+size]='\0';
   }
else
   {
   size=strlen(state);
   for (i=0; i < LINK_SIZE; i++)
       state[i+size]=local_link[i];
   state[LINK_SIZE+size]='\0';
   }

}

extern UnfoldLink(local_link,state)  /*put link on right */

char local_link[],state[];

{
int i,size,size2;
   size=strlen(state);
   size2=strlen(local_link);
   for (i=0; i < size2; i++)
       state[i+size]=local_link[(LINK_LINK_SIZE-1)-i];
   state[size2+size]='\0';
}




