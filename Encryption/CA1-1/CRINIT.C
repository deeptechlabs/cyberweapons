/* file crinit.c */
#include "crtype.h"
#include "crutil.h"
#include "crinit.h"

set_for_radius()
{
radius_times_2=2*radius;
neighborhood_size=radius_times_2+1;
number_of_partial_neighborhoods=list_of_powers_of_2[radius_times_2];
number_of_neighborhoods=list_of_powers_of_2[neighborhood_size];
high_bit_mask = (LOW_BIT_MASK << radius_times_2-1);
decrypt_bit_cut_off=number_of_neighborhoods-1;
encrypt_bit_cut_off=number_of_partial_neighborhoods-1;
neighborhood_mask=2*high_bit_mask;
}


extern set_for_link()

{
radius=3;
set_for_radius();
}


extern set_for_block()

{
radius=5;
set_for_radius();
}


extern initialize() /* various initializations */

{
make_list_of_powers_of_2();

/* calculate parameters which depend on the radius */

set_for_block();

}




extern set_key_values(l_key,r_key,toggle,b_bits) /* sets two key values */

char l_key[],r_key[];
int toggle;
int b_bits[];
{
int t2,num;
key=&(l_key[0]);
num=b_bits[toggle];
    if (num IS 0)
       {
       *(key+toggle)=ZERO;
       *(key+toggle+number_of_partial_neighborhoods)=ONE;
       }
    else
       {
       *(key+toggle)=ONE;
       *(key+toggle+number_of_partial_neighborhoods)=ZERO;
       }
key=&(r_key[0]);
num=b_bits[number_of_partial_neighborhoods-toggle];
t2=2*toggle;
    if (num IS 0)
       {
       *(key+t2)=ZERO;
       *(key+t2+1)=ONE;
       }
    else
       {
       *(key+t2)=ONE;
       *(key+t2+1)=ZERO;
       }
}





extern generate_a_rand_string(string,size)

char string[];
int size;

{

int i,num;


for (i=0; i< size; i++)
    {
    num=(random()&01);
    if (num IS 0) string[i]=ZERO; else  string[i]=ONE;
    }
}





extern test_balance(b_bits)
int b_bits[];
{
int i,total;
total=0;
for (i=0; i < number_of_partial_neighborhoods; i++)
    total+=b_bits[i];

if (total != list_of_powers_of_2[radius_times_2-1])
printf(" unbalanced: is %d, should be %d \n",total,list_of_powers_of_2[radius_times_2-1]);

}


extern generate_balanced_bits(b_bits)

int b_bits[];
{
int i,total;
int diff,where,too_many;
total=0;
for (i=0; i< number_of_partial_neighborhoods; i++)
    {
    b_bits[i]=(random()&01);
    total+=b_bits[i];
    }
    diff=total- list_of_powers_of_2[radius_times_2-1];
    if (diff > 0) too_many=1; else { too_many=0; diff=-diff; }
/* + means too many ones, - too many zeros */
while (diff > 0)
     {
if (radius IS 5)
     where=random()&1023;
else
     where=random()&63;
     if (b_bits[where] IS too_many)
	{
	b_bits[where]=1-b_bits[where];
	diff--;
	}
     }

test_balance(b_bits);

}





extern generate_the_keys(b_bits,l_key,r_key)

int b_bits[];
char l_key[],r_key[];

{

int i;
generate_balanced_bits(b_bits);

for (i=0; i< number_of_partial_neighborhoods; i++)
    set_key_values(l_key,r_key,i,balanced_bits); /* sets two key values */
}



