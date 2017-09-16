/*
 $Id: random.c,v $

 This program is public domain and was written by William S. England
 (Oct 1988).  It is based on an article by:

 Stephen K. Park and Keith W. Miller. RANDOM NUMBER GENERATORS:
 GOOD ONES ARE HARD TO FIND. Communications of the ACM,
 New York, NY.,October 1988 p.1192

 Modifications;

 $Log: random.c,v $

######

 The following is a portable c program for generating random numbers.
 The modulus and multiplier have been extensively tested and should
 not be changed except by someone who is a professional Lehmer generator
 writer.  THIS GENERATOR REPRESENTS THE MINIMUM STANDARD AGAINST WHICH
 OTHER GENERATORS SHOULD BE JUDGED. ("Quote from the referenced article's
 authors. WSE" )
*/

/*
**  These are pre-calculated  below to compensate for c 
**  compilers that may overflow when building the code.
**
**  q = (m / a)
**  r = (m % a)
*/

/*
** To build the generator with the original ACM
** article's numbers use -DORIGINAL_NUMBERS when compiling.
**
** Original_numbers are the original published m and q in the
** ACM article above.  John Burton has furnished numbers for
** a reportedly better generator.  The new numbers are now
** used in this program by default.
*/

#ifndef ORIGINAL_NUMBERS
#define	m  (unsigned long)2147483647
#define	q  (unsigned long)44488

#define	a (unsigned int)48271
#define	r (unsigned int)3399

#define successfulltest 399268537
#endif

#ifdef ORIGINAL_NUMBERS
#define	m  (unsigned long)2147483647
#define	q  (unsigned long)127773

#define	a (unsigned int)16807
#define	r (unsigned int)2836

#define successfulltest 1043618065
#endif

/*
** F(z)	= (az)%m
**	= az-m(az/m)
**
** F(z)  = G(z)+mT(z)
** G(z)  = a(z%q)- r(z/q)
** T(z)  = (z/q) - (az/m)
**
** F(z)  = a(z%q)- rz/q+ m((z/q) - a(z/m))
** 	 = a(z%q)- rz/q+ m(z/q) - az
*/

unsigned long seed;

void srand( /* unsigned long*/ initial_seed)
unsigned long initial_seed;
{
    seed = initial_seed; 
}
/*
**
*/
unsigned long rand(/*void*/){

register
int 	lo, hi, test;

    hi   = seed/q;
    lo   = seed%q;

    test = a*lo - r*hi;

    if (test > 0)
	seed = test;
    else
	seed = test+ m;

    return seed;
}

#ifdef TESTRAND
#include <stdio.h> 
/*  
**   The result of running this program should be
**   "successfulltest".  If this program does not yield this
**   value then your compiler has not implemented this
**   program correctly.
**   
**   To compile with test option under unix use; 'cc -DTESTRAND random.c'
**
**   Be sure to compile without test option for use in applications.
**   ( Now why did I have to say that ??? )
*/

main(/*void*/)
{
unsigned 
long	n_rand;

register int 	i;
int	success = 0;

    srand(1);

    for( i = 1; i <= 10001; i++){
        n_rand = rand();

        if( i> 9998)  
	    printf("Sequence %5i, Seed= %10i\n", i, seed ); 

	if( i == 10000) 
	    if( seed == successfulltest ) 
		success = 1;
    }

    if (success){
	printf("The random number generator works correctly.\n\n");
	exit(0);
    }else{
	printf("The random number generator DOES NOT WORK!\n\n");
	exit(1);
    }
}
#endif
