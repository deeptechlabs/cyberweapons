From bbowen@megatest.com Mon Jan  2 23:00:29 CST 1995
Article: 28209 of sci.crypt
Newsgroups: sci.crypt
Path: chinet!pagesat.net!dfw.net!convex!cs.utexas.edu!howland.reston.ans.net!news.sprintlink.net!pipex!uunet!psinntp!megatest!bbowen
From: bbowen@megatest.com (Bruce Bowen)
Subject: Bug in "BIGNUM", new code.
Message-ID: <D1JBLH.69@megatest.com>
Organization: Megatest Corporation
Date: Wed, 28 Dec 1994 19:02:42 GMT
Lines: 2152

-----BEGIN PGP SIGNED MESSAGE-----


  I discovered a bug in my "BIGNUM" c++ class for arbitrarily large
integers.  It involved negation of numbers of the form 2^(n*dgt_sze)
where n is an integer.  The following version fixes the problem. I've
also added an option to the "main" driver that allows a command line
argument to select the I/O base {8, 10, 16}.  The main driver is
essentially an RPN calculator.

- -------------------------------------CUT HERE--------------------------------------
//	Author:	Bruce Bowen	bbowen@megatest.com
//
//	Distributed under the terms of the Gnu General Public License
//
//	History
//
//  Last edited
//	05 May 1994
// 	03 July 1994   Cleaned up some bogus warning message triggers.
//	19 July 1994   Minor Pre-processor improvements.
//      25 Dec 1994    Fixed bug in "negate()" that caused problem with -2^bit_lgth.
//                     Added command line option in "main" driver to allow I/O base selection.

#include	<iostream.h>
#include	<iomanip.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<ctype.h>


// "CLAMP" is used to limit blow up during various exponentiation functions.
#define CLAMP "0x100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

// Default I/O base is 10 (decimal).
#ifndef IO_BASE
    int		dflt_base = 10;
#else  
    int		dflt_base = IO_BASE;
#endif

const	bit_lgth = 15;			/* Log 2 of Base */
const	long dgt_sze = 1l << bit_lgth;	/* Base (must be power of 2) */
const	long dgt_M_1 = dgt_sze - 1;

const   true = 1;
const   false = 0;

struct	s1	// A simple doubly linked list of long integers.
{
    s1			*nxt;
    s1			*prv;
    unsigned long	current;
    s1(s1*);	// Constructor. Creates and inserts into list after s1*.
    ~s1();	// Destructor.  Splices element out of list and deletes.
};

struct  char_lst	// A simple doubly linked list of character.
{
    char_lst	*nxt;
    char_lst	*prv;
    char	io_digit;
    char_lst(char_lst*);
    ~char_lst();
};


class	bignum
{
    int		lgth;     // Total number of digits in number.
    s1		*digit;   // Doubly linked list of digits.

    bignum&	normalize(const int& = 1);

    public:

    void	dump();			// Dumps the data structure.  Useful for debugging.

    void	negate();		// Makes number negative.
    void	string_in(char*);	// Convert a string to bignum.
    char*	output(int = dflt_base) const;

    /*  Various constructor functions. */

    bignum() : digit(new s1(NULL)), lgth(0) { digit->current = 0;}
    bignum(const long&);
//    bignum(char*);
    bignum(const bignum&);

    ~bignum();	//  ... and the destructor.


    /*  Various member unary operator functions. */

    bignum&  operator++();	// Prefix increment.
    bignum   operator++(int);	// Postfix increment.
    bignum&  operator--();	// Prefix decrement.
    bignum   operator--(int);	// Postfix decrement.
    bignum&  operator+() {return *this;}	// Does nothing;
    bignum   operator~() const;			// Bitwise compliment.
    int	     operator!() const;

    /*  Various member binary operator functions. */

    bignum&  operator=(const bignum&);
    bignum&  operator+=(const bignum&);
    bignum&  operator-=(const bignum&);
    bignum&  operator*=(const bignum&);
    bignum&  operator/=(const bignum&);
    bignum&  operator%=(const bignum&);
    bignum&  operator<<=(const long&);
    bignum&  operator>>=(const long&);

    unsigned long operator[](const int&) const;

    /*  Various friend operator function. */

    friend bignum operator+(bignum, bignum);		// Addition.
    friend bignum operator-(const bignum&, bignum);	// Subtraction.
    friend bignum operator*(bignum, bignum);		// Multiplication.
    friend bignum operator/(bignum, bignum);		// Division.
    friend bignum operator%(bignum, bignum);		// Modulus
    friend bignum operator^(bignum, bignum);		// Bitwise exclusive or.
    friend bignum operator&(bignum, bignum);		// Bitwise and.
    friend bignum operator|(bignum, bignum);		// Bitwise or.
    friend bignum operator>>(bignum, const long&);	// Right shift.
    friend bignum operator<<(bignum, const long&);	// Left shift.
    friend bignum operator-(bignum);			// Unary negation.

    friend int    operator==(bignum, bignum);	// Comparison.
    friend int    operator!=(const bignum& n1, const bignum& n2);
    friend int    operator>(const bignum&, const bignum&);
    friend int    operator>=(const bignum&, const bignum&);
    friend int	  operator<(const bignum&, const bignum&);
    friend int	  operator<=(const bignum&, const bignum&);
    friend int    operator&&(const bignum& n1, const bignum& n2)
	{return ((!!n1) && (!!n2)); }
    friend int    operator||(const bignum& n1, const bignum& n2)
	{return ((!!n1) || (!!n2)); }

    friend bignum a_exp_b_mod_c(bignum, const bignum&, const bignum&);
    friend bignum a_exp_b(const bignum&, const bignum&);

    friend ostream& operator<<(ostream&, bignum); // Output function.
};


/********************************************************************/
/*    The following routine dumps the data structure to stderr      */

void	 bignum::dump()


{
    s1			*tmp;
    int			i;
    
    fprintf(stdout, "Length  = %2d: Sign digit = %08lx\n", lgth, digit->current);
    
    for(tmp = digit->nxt, i=lgth-1; tmp != digit; i--, tmp = tmp->nxt)
    {
	fprintf(stdout, "        = %2d:      digit = %08lx\n", i, tmp->current);
    }
};



/************************************************************/
/*    The following routine propogates and sums carries.    */
/*  "Extend allows number growth vs "rolling" off the top.  */

bignum&	 bignum::normalize(const int& extend)

{
    s1			*tmp;
    unsigned long	upper;


    for(tmp = digit->prv, lgth = 0; tmp != digit; tmp = tmp->prv)
    {
	++lgth;
	upper = tmp->current >> bit_lgth; 	 // Get upper bits.
	tmp->current = tmp->current & dgt_M_1; // Keep lower bits.

	if((tmp->prv != digit) || (upper == 0))	 // No need to extend.
	{
	    tmp->prv->current += upper;
	}
	else if(extend)		// Need to extend, and extend allowed.
	{
	    new s1(digit);
	    tmp->prv->current = upper;
	}
	else 	// "Need to extend but extend not allowed. Roll off.
	{
	    digit->current = !digit->current; // 2's compliment carry.
	}
    }

/*    The following loop removes leading sign digits from a number    */

    tmp = digit->nxt;
    if(digit->current == 0)		// Positive number.
    {
	while(tmp != digit)
	{
	    if(tmp->current == 0)	{
		tmp = tmp->nxt;
		*this >>= -1;		// Chop off MSDs.
	    }
	    else
	    {
		break;
	    }
	}
    }
    else				// Negative number. Two's complement.
    {
        digit->current = 1; // Make "1", not just "non-zero".
	while(tmp != digit)
	{
	    if(tmp->current == dgt_M_1)
	    {
		tmp = tmp->nxt;
		*this >>= -1;		// Chop off MSDs.
	    }
	    else
	    {
		break;
	    }
	}
    }
    return(*this);
}


/****************************************************************/
/*			Binary Addition				*/

bignum operator+( bignum addend1, bignum addend2 )

{
    bignum	*addend_max, *addend_min, sum;
    s1		*tmp_max, *tmp_min;
    unsigned	sign;

    sum = 0;

    if(addend2.lgth >= addend1.lgth)
    {
	addend_max = &addend2;		// "Points to longer addend.
	addend_min = &addend1;		// "Points to shorter addend.
    }
    else
    {
	addend_max = &addend1;		// "Points to longer addend.
	addend_min = &addend2;		// "Points to shorter addend.
    }

    sign = addend_min->digit->current ? 1 : 0;    // Get sign of shortest number.

    /* Sign extend longest number by one digit to handle carries.	*/
    /* This is necessary because I'm not allowing "normalize" to do	*/
    /* my extending in this case because of two's compliment addition.	*/

    *addend_max <<= -1;   // Add leading sign digit (negative shift lefts append sign digits to left).

    tmp_max = addend_max->digit;  // Loop (sum) over shorter addend.
    for(tmp_min = addend_min->digit->prv; tmp_min != addend_min->digit; tmp_min = tmp_min->prv)
    {
	tmp_max = tmp_max->prv;
	new s1(sum.digit)->current = tmp_min->current + tmp_max->current; //Add corresponding digits.
	++sum.lgth;
    }

    // Finish looping (summing) over longer addend.
    for(tmp_max = tmp_max->prv; tmp_max != addend_max->digit; tmp_max = tmp_max->prv)
    {
	new s1(sum.digit)->current = tmp_max->current + (sign ? dgt_M_1 : 0);
	++sum.lgth;
    }

    /* Logically "Exclusive or" the final carry bit (twos compliment). */

    sum.digit->current = addend1.digit->current ? !addend2.digit->current : addend2.digit->current;
    sum.normalize(0);

    return(sum);	// Return by value.
}


/****************************************************************/
/*  		Unary negation. Two's compliment.		*/
/*	  Algorithm:  Compliment the bits, then add "1".	*/
/*								*/
/*  Caution,  "0" must be normalized for this routine to work.  */

void  bignum::negate()

{
    s1		*tmp;

    for(tmp = digit->prv; tmp != digit; tmp = tmp->prv) {
	tmp->current = tmp->current ^ dgt_M_1;
    }

    if(digit->prv == digit)	{	//  "0"  or "-1"
	if(digit->current)	{	// "-1", not "0".
	    new s1(digit);
	    lgth = 1;
	    digit->prv->current = 1;
	    digit->current = !digit->current;
	}
    }
    else	{
	++digit->prv->current;	// Increment the complimented number.
	digit->current = !digit->current;
	normalize(1);
    }
}

/****************************************************************/
/*  		Unary negation. Friend function.		*/
/*	  Algorithm:  Compliment the bits, then add "1".	*/

bignum	operator-( bignum subtrahend )

{
    subtrahend.negate();
    return subtrahend;    //Return by value.
}

/****************************************************************/
/*			Binary subtraction			*/

bignum	operator-( const bignum& minuend, bignum subtrahend )

{
    bignum 	tmp, difference;

    subtrahend.negate();
    difference = minuend + subtrahend;

    return(difference);
}


/****************************************************************/
/*			Binary multiplication			*/

bignum	operator*( bignum factr1, bignum factr2 )
{
    bignum	product;
    s1		*tmp_max, *tmp_min, *tmp_rslt, *tmp, *tmp1;
    int		i, j;
    int		min, max;
    unsigned long	sign1, sign2;

    product = 0;

    // Record the sign of factors and make factors positive.

	 if(0 != (sign1 = factr1.digit->current))  factr1 = -factr1;
	 if(0 != (sign2 = factr2.digit->current))  factr2 = -factr2;

    if(factr2.lgth >= factr1.lgth)
    {
	max = factr2.lgth;
	min = factr1.lgth;
	tmp_max = factr2.digit;
	tmp_min = factr1.digit;
    }
    else
    {
	max = factr1.lgth;
	min = factr2.lgth;
	tmp_max = factr1.digit;
	tmp_min = factr2.digit;
    }

    tmp  = tmp_min;

    for(i=0; i<min; ++i)		// Outer loop.
    {
	tmp = tmp->nxt;
	product <<= 1;			// Shift left one digit.

	tmp_rslt = product.digit;
	tmp1 = tmp_max;
	for(j=0; j<max; ++j)		// Inner loop.
	{
	   tmp1 = tmp1->prv;
	   tmp_rslt = tmp_rslt->prv;
	   if(tmp_rslt == product.digit)  // Add more digits
	   {
		product <<= -1;			// Add leading zero (denormalizes number).
		tmp_rslt = product.digit->nxt;
	   }

	   tmp_rslt->current += tmp->current * tmp1->current;
	}
	product.normalize(1);	// Allow length extention since no problem
				// with signs, both numbers positive.
    }
    if(sign1 ? !sign2 : sign2)	product = -product;

    return(product);	// Return by value.
}


/****************************************************************/
/*			Binary division				*/

bignum	operator/( bignum dividend, bignum divisor )

{
    bignum	subtrahend, quotient;
    s1		*tmp, *tmp_q;

    int			i, j, q_position;
    int			old_dvd_lgth, dvd_lgth, loop_count;
    unsigned	long	nrml;
    unsigned	long	v1, v2, u0, u1, u2;
    unsigned	long	sign1, sign2;

    quotient = 0;

    if(0 != (sign1 = dividend.digit->current)) dividend = -dividend;
    if(0 != (sign2 = divisor.digit->current))   divisor = -divisor;

    switch(divisor.lgth)	{

	case 0:	cerr << "Divide by zero error.";
		break;

	case 1:	v1 = divisor.digit->nxt->current;  // Short division algorithm.
		u0 = 0;
		tmp = dividend.digit;
		for(i=0; i<dividend.lgth; ++i)
		{
		    tmp = tmp->nxt;
		    u0 = dgt_sze * u0  +  tmp->current;
		    new s1(quotient.digit->prv)->current = u0/v1;
		    u0 = u0 % v1;
		    ++quotient.lgth;
		}
		break;

	default:	// Long division algorithm. UGHHHHHH!!

/************************************************************************/

    old_dvd_lgth = dividend.lgth;
 
    dvd_lgth = old_dvd_lgth + 1; // This is needed to keep track of new
			         // dividend length during partial subtractions.

//  The multiplicative constant "nrml" makes the MSD of the
//  divisor >= Radix/2.   This makes the division more efficient.
//  See Knuth "Seminumerical Algorithms": Pg 257-258.

    nrml = dgt_sze / (divisor.digit->nxt->current + 1);

    divisor *= nrml;
    dividend *= nrml;

    if(dividend.lgth == old_dvd_lgth)  // Insert a leading "0" in dividend.
    {
	dividend <<= -1;	// Insert leading zero (denormalizes number).
    }

/*		We are now finished with the scaling.			*/

    q_position = dividend.lgth - divisor.lgth;

    v1 = divisor.digit->nxt->current;		// Get two MSDs of divisor.
    v2 = divisor.digit->nxt->nxt->current;

    loop_count = old_dvd_lgth - divisor.lgth;
    for(j=0; j <= loop_count; ++j)
    {
	u0 = dividend.digit->nxt->current;	// Get three MSDs of dividend.
	u1 = dividend.digit->nxt->nxt->current;
	u2 = dividend.digit->nxt->nxt->nxt->current;

	// Calculate new quotient digit candidate.

	(tmp_q = new s1(quotient.digit->prv))->current =
		 (v1 == u0) ? dgt_M_1 : ((dgt_sze * u0 + u1)/v1);

	++quotient.lgth;

	// Special quick subtest of candidate before final test. See Knuth.

	while((v2 * tmp_q->current) >
	    (((dgt_sze * u0  + u1 - tmp_q->current * v1)*dgt_sze + u2)))  // Oops! cadidate too large, start reducing.
	{
	    --tmp_q->current;
	}

	/* Calculate new subtrahend,  = new quotient digit * divisor	  */

	subtrahend = divisor * tmp_q->current;

	/* Pad subtrahend with trailing "0"s to shift left to proper position  */

	subtrahend <<= --q_position;
	subtrahend.normalize(1);

	dividend -= subtrahend; // Calculate new dividend.

	if(dividend.digit->current)    // The subtraction was negative.
	{				  // Knuth's quick test failed!
	    --tmp_q->current;
	    dividend += (divisor << q_position);  // Add back one divisor.
	}

	/* The following step is necessary because we need to see the	*/
	/* next digit position even if it is zero.			*/

	dividend <<= -(--dvd_lgth - dividend.lgth); // Pad new dividend with leading zeros.
      }
    }

    quotient.normalize(1);

    if(sign1 ? !sign2 : sign2)	quotient = -quotient;

    return(quotient);	// Return by value;
}

/****************************************************************/
/*			Binary modulus				*/

bignum	operator%( bignum dividend, bignum divisor )

{
    bignum		subtrahend;
    s1			*tmp;
    unsigned	long	tmp_q;

    int			i, j, q_position;
    int			old_dvd_lgth, dvd_lgth, loop_count;
    unsigned	long	nrml;
    unsigned	long	v1, v2, u0, u1, u2;
    unsigned	long	sign1, sign2;

    if(0 != (sign1 = dividend.digit->current)) dividend = -dividend;
    if(0 != (sign2 = divisor.digit->current))   divisor = -divisor;

    switch(divisor.lgth)	{

	case 0:	cerr << "Divide by zero error.";
		break;

	case 1:	v1 = divisor.digit->nxt->current;  // Short division algorithm.
		u0 = 0;
		tmp = dividend.digit;
		for(i=0; i<dividend.lgth; ++i)
		{
		    tmp = tmp->nxt;
		    u0 = dgt_sze * u0  +  tmp->current;
		    u0 = u0 % v1;
		}
		dividend = u0;
		break;

	default:	// Long division algorithm. UGHHHHHH!!


/*  The following loop normalizes the divisor and dividend by making the  */
/*  MSD of the divisor >= Radix/2.   This makes the division more	  */
/*  efficient.	 See Knuth "Seminumerical Algorithms": Pg 257-258.	  */

    old_dvd_lgth = dividend.lgth;
 
    dvd_lgth = old_dvd_lgth + 1; // This is needed to keep track of new
			         // dividend length during partial subtractions.

    nrml = dgt_sze / (divisor.digit->nxt->current + 1);

    divisor *= nrml;
    dividend *= nrml;

    if(dividend.lgth == old_dvd_lgth)  // Insert a leading "0" in dividend.
    {
	dividend <<= -1;	// Insert leading zero (denormalizes number).
    }

    q_position = dividend.lgth - divisor.lgth;

    /*	    We are now finished with the normalization.		*/


    v1 = divisor.digit->nxt->current;		// Get two MSDs of divisor.
    v2 = divisor.digit->nxt->nxt->current;

    loop_count = old_dvd_lgth - divisor.lgth;
    for(j=0; j <= loop_count; ++j)
    {
	u0 = dividend.digit->nxt->current;	// Get three MSDs of dividend.
	u1 = dividend.digit->nxt->nxt->current;
	u2 = dividend.digit->nxt->nxt->nxt->current;


	// Calculate new quotient digit candidate.

	tmp_q =  (v1 == u0) ? dgt_M_1 : ((dgt_sze * u0 + u1)/v1);

	// Special quick subtest of candidate before final test. See Knuth.
	while((v2 * tmp_q) >
	      (((dgt_sze * u0  + u1 - tmp_q * v1)*dgt_sze + u2)))  // Opps! cadidate too large, start reducing.
	{
	    --tmp_q;
	}

/*	Calculate new subtrahend,  = new quotient digit * divisor	*/

	subtrahend = divisor * tmp_q;

/*	Pad subtrahend with trailing "0"s to shift left to proper position  */

	subtrahend <<= --q_position;
	subtrahend.normalize(1);

	dividend -= subtrahend; // Calculate new dividend.

	if(dividend.digit->current)    // The subtraction was negative.
	{				  // Knuth's quick test failed!
	    --tmp_q;
	    dividend += (divisor << q_position);  // Add back one divisor.
	}

	dividend <<= -(--dvd_lgth - dividend.lgth); // Pad new dividend with leading zeros.
      }

      /* The following loop is necessary to undo the multiply by "nrml" above.	*/

      u0 = 0;	// The following loop is short division.
      for(tmp = dividend.digit->nxt; tmp != dividend.digit; tmp = tmp->nxt)
      {
	u0 = dgt_sze * u0 + tmp->current;
	tmp->current = u0/nrml;
	u0 = u0 % nrml;
      }
    }

    dividend.normalize(0);

    return(dividend);		// Return by value;
}

/****************************************************************/
/*			Bitwise "and"				*/

bignum	operator&( bignum n1, bignum n2 )
{
    bignum 	rslt, *arg_max, *arg_min;
    s1		*tmp1, *tmp2, *rtmp;
    int		pads;

    if(n1.lgth >= n2.lgth)	// Find longest argument and pad smaller.
    {
	arg_max = &n1;
	arg_min = &n2;
    }
    else
    {
	arg_max = &n2;
	arg_min = &n1;
    }

	 if(0 != (pads = arg_min->lgth - arg_max->lgth))  *arg_min <<= pads;

    rslt <<= arg_max->lgth;	// Make result same length as longest argument.
    tmp1 = n1.digit;
    tmp2 = n2.digit;
    rtmp = rslt.digit;
    do
    {
	rtmp->current = tmp1->current & tmp2->current;
	tmp1 = tmp1->nxt;
	tmp2 = tmp2->nxt;
	rtmp = rtmp->nxt;
    } while(tmp1 != n1.digit);

    return rslt;		// Return by value.
}

/****************************************************************/
/*			Bitwise "or"				*/

bignum	operator|( bignum n1, bignum n2 )
{
    bignum 	rslt, *arg_max, *arg_min;
    s1		*tmp1, *tmp2, *rtmp;
    int		pads;

    if(n1.lgth >= n2.lgth)	// Find longest argument and pad smaller.
    {
	arg_max = &n1;
	arg_min = &n2;
    }
    else
    {
	arg_max = &n2;
	arg_min = &n1;
    }

	 if(0 != (pads = arg_min->lgth - arg_max->lgth))  *arg_min <<= pads;

    rslt <<= arg_max->lgth;	// Make result same length as longest argument.
    tmp1 = n1.digit;
    tmp2 = n2.digit;
    rtmp = rslt.digit;
    do
    {
	rtmp->current = tmp1->current | tmp2->current;
	tmp1 = tmp1->nxt;
	tmp2 = tmp2->nxt;
	rtmp = rtmp->nxt;
    } while(tmp1 != n1.digit);

    return rslt;		// Return by value.
}

/****************************************************************/
/*			Bitwise "exclusive or"				*/

bignum	operator^( bignum n1, bignum n2 )
{
    bignum 	rslt, *arg_max, *arg_min;
    s1		*tmp1, *tmp2, *rtmp;
    int		pads;

    if(n1.lgth >= n2.lgth)	// Find longest argument and pad smaller.
    {
	arg_max = &n1;
	arg_min = &n2;
    }
    else
    {
	arg_max = &n2;
	arg_min = &n1;
    }

	 if(0 != (pads = arg_min->lgth - arg_max->lgth))  *arg_min <<= pads;

    rslt <<= arg_max->lgth;	// Make result same length as longest argument.
    tmp1 = n1.digit;
    tmp2 = n2.digit;
    rtmp = rslt.digit;
    do
    {
	rtmp->current = tmp1->current ^ tmp2->current;
	tmp1 = tmp1->nxt;
	tmp2 = tmp2->nxt;
	rtmp = rtmp->nxt;
    } while(tmp1 != n1.digit);

    return rslt;		// Return by value.
}


/****************************************************************/
/*			Bitwise "compliment"			*/

bignum	bignum::operator~() const
{
    bignum 	rslt;
    s1		*tmp, *rtmp;

    rslt <<= lgth;	// Make result same length as argument.
    rtmp = rslt.digit;
    tmp = digit;
    do
    {
    	rtmp->current = ~tmp->current;
    	tmp = tmp->nxt;
    	rtmp = rtmp->nxt;
    } while(tmp != digit);

    return rslt;		// Return by value.
}

/************************************************************************/
/*			Constructor for class s1			*/

s1::s1(s1* pntr)

{
    if(pntr == NULL)	{
	prv = this;
	nxt = this;
    }
    else 	{
	prv = pntr;
	nxt = pntr->nxt;
	nxt->prv = this;
	pntr->nxt = this;
    }
}


/************************************************************************/
/*			Destructor for class s1				*/

s1::~s1()

{
   prv->nxt = nxt;
   nxt->prv = prv;
}


/************************************************************************/
/*	  Class "bignum" conversion definition: String Input		*/

void	bignum::string_in(char* num_strg)

{
    int		base;
    int		sign = 0;
    int		DONE = 0;

    while(*num_strg != '\0')		// Eliminate leading whitespace.
    {
	if(isspace(*num_strg))
	{
	    ++num_strg;
	}
	else
	{
	    break;
	}
    }

    if(*num_strg == '-')		// See if negative number.
    {
	sign = 1;
	++num_strg;
    }

    if(strnicmp(num_strg, "0x", 2) == 0)
    {
	base=16;
	++num_strg;
	++num_strg;
    }
    else if(strnicmp(num_strg, "0", 1) == 0)
    {
	base=8;
	++num_strg;
    }
    else
    {
	base=10;
    }

    while(isalnum(*num_strg) && !DONE)
    {
	switch(*num_strg)
	{
	    case '0':
	    case '1':
	    case '2':
	    case '3':
	    case '4':
	    case '5':
	    case '6':
	    case '7':
	    case '8':
	    case '9':
		*this = base*(*this) + (*num_strg - '0');
		++num_strg;
		break;

	    case 'a':
	    case 'b':
	    case 'c':
	    case 'd':
	    case 'e':
	    case 'f':
		*this = base*(*this) + (*num_strg - 'a' + 0xa);
		++num_strg;
		break;

	    case 'A':
	    case 'B':
	    case 'C':
	    case 'D':
	    case 'E':
	    case 'F':
		*this = base*(*this) + (*num_strg - 'A' + 0xa);
		++num_strg;
		break;
	    default:
		DONE = 1;
	}
    }
    if(sign)	negate();
}


/************************************************************************/
/*		Class "bignum" destructor definition. 			*/

bignum::~bignum()

{
    if(digit != NULL)
    {
	while(digit->nxt != digit)  // Walk through the list deleting elements.
    	{
    	    delete digit->nxt;	//Destructor for s1 instance updates list.
    	}
    	delete digit;
    }
}


/************************************************************************/
/*		Class "bignum" constructor definitions			*/

bignum::bignum(const long& value)

{
    lgth = 1;
    digit = new s1(NULL);
    new s1(digit);
    if(value >= 0)
    {
        digit->current = 0;
	digit->nxt->current = value;
	normalize(1);
    }
    else
    {
	digit->current = 0;
	digit->nxt->current = -value;
	normalize(1);
	negate();
    }
}


/************************************************************************/
/*		Class "bignum" constructor definitions			*/  
/*			Copy Constructor				*/

bignum::bignum(const bignum& in_nmbr)

{
    s1	*tmp;

    lgth = in_nmbr.lgth;

    if(in_nmbr.digit != NULL)
    {
	digit = new s1(NULL);
	digit->current = in_nmbr.digit->current;
	
	for(tmp=in_nmbr.digit->nxt; tmp != in_nmbr.digit; tmp = tmp->nxt)
	{
	    new s1(digit->prv)->current = tmp->current;
	}
    }
    else
    {
    	digit = NULL;
    }
}

/************************************************************************/
/*		Class "bignum" assignment definitions			*/
/*									*/
/*  This routine tries to keep as much of the "assigned to" instance    */
/*  intact as possible.  Corresponding digit addresses are preserved.   */

bignum&	   bignum::operator=( const bignum& in_nmbr )

{
    s1		*tmp, *tmp2;
    int		surplus_digits;

    if(this == &in_nmbr)	// Self assignment
    {
    }
    else
    {		// Adjust space requirements.

	surplus_digits = lgth - in_nmbr.lgth;
	if(surplus_digits > 0)		// Too many digits.
	{
	    *this >>= -surplus_digits;	// Chop off extra leading digits (Argument negative).
	}
	else if(surplus_digits < 0)	// Not enough digits.
	{
	    *this <<= surplus_digits;	// Pad extra leading digits (Argument negative).
	}
	// Done adjusting space requirements.

	digit->current = in_nmbr.digit->current;
	tmp2 = digit;
	for(tmp=in_nmbr.digit->nxt; tmp != in_nmbr.digit; tmp = tmp->nxt)
	{
	    tmp2 = tmp2->nxt;
	    tmp2->current = tmp->current;	// Assign corresponding values.
	}
    }
    return	*this;	// Return by reference.
}


/****************************************************************/
/*			Shift left operator.			*/
/*	Note: Observe behaviour with negative shift values!	*/

bignum     operator<<(bignum  in_nmbr, const long& shift_value)
{
    long	i;
    s1		*tmp;

    if(shift_value > 0)		// Shift left whole digits. Add zeros.
    {
	for( i = 0; i < shift_value; i++ )
	{
	    tmp = new s1(in_nmbr.digit->prv);
	    tmp->current = 0;
	    ++in_nmbr.lgth;
	}
    }
    else if(shift_value < 0)	// Adds leading sign digits. Does NOT change value.
    {
	for( i = 0; i > shift_value; i-- )
	{
	    tmp = new s1(in_nmbr.digit);
	    tmp->current = in_nmbr.digit->current ? dgt_M_1 : 0;
	    ++in_nmbr.lgth;
	}
    }
    return in_nmbr;
}


/****************************************************************/
/*		Shift left assignment operator.			*/

bignum&   bignum::operator<<=(const long& shift_value)
{
    long	i;
    s1		*tmp;

    if(shift_value > 0)		// Shift left whole digits. Add zeros.
    {
	for( i = 0; i < shift_value; i++ )
	{
	    tmp = new s1(digit->prv);
	    tmp->current = 0;
	    ++lgth;
	}
    }
    else if(shift_value < 0)	// Adds leading sign digits. Does NOT change value.
    {
	for( i = 0; i > shift_value; i-- )
	{
	    tmp = new s1(digit);
	    tmp->current = digit->current ? dgt_M_1 : 0;
	    ++lgth;
	}
    }
    return *this;	// Return by reference.
}

/****************************************************************/
/*			Shift right operator.			*/
/*	Note: Observe behaviour with negative shift values!	*/

bignum operator>>(bignum in_nmbr, const long& shift_value)
{
	 long	i;

    if(in_nmbr.digit->nxt != in_nmbr.digit)
    {
	if(shift_value > 0)	  // Shift right whole digits. Chop off LSDs.
	{
	    for( i = 0; i < shift_value; i++ )
	    {
		delete in_nmbr.digit->prv;
		--in_nmbr.lgth;
	    }
	}
	else if(shift_value < 0)   // Chop off MSDs.
	{
	    for( i = 0; i > shift_value; i-- )
	    {
		delete in_nmbr.digit->nxt;
		--in_nmbr.lgth;
	    }
	}
    }
    return in_nmbr;	// Return by value
}

/****************************************************************/
/*		Shift right assignment operator.		*/

bignum&  bignum::operator>>=(const long& shift_value)
{
	 long	i;

    if(digit->nxt != digit)
    {
	if(shift_value > 0)	  // Shift right whole digits. Chop off LSDs.
	{
	    for( i = 0; i < shift_value; i++ )
	    {
		delete digit->prv;
		--lgth;
	    }
	}
	else if(shift_value < 0)   // Chop off MSDs.
	{
	    for( i = 0; i > shift_value; i-- )
	    {
		delete digit->nxt;
		--lgth;
	    }
	}
    }
    return *this;	// Return by reference.
}

/****************************************************************/
/*		   Prefix Increment operator.			*/

bignum&	   bignum::operator++()		// Prefix increment.

{
    if(digit == NULL)  cerr << "Unassigned bignum instance\n";
    else
    {
    	*this = *this + 1;
    }
    return *this;
}

/****************************************************************/
/*		    Postfix Increment operator.			*/

bignum	   bignum::operator++(int jnk)	// Postfix increment.

{
    bignum tmp = *this;

    if(digit == NULL)  cerr << "Unassigned bignum instance\n";
    else
    {
    	*this = *this + 1;
    }
    return tmp;
}

/****************************************************************/
/*		    Prefix Decrement operator.			*/

bignum&	   bignum::operator--()		// Prefix increment.

{
    if(digit == NULL)  cerr << "Unassigned bignum instance\n";
    else
    {
    	*this = *this - 1;
    }
    return *this;
}

/****************************************************************/
/*		Postfix Decrement operator.			*/

bignum	   bignum::operator--(int jnk)	     // Postfix increment.

{
    bignum tmp = *this;

    if(digit == NULL)  cerr << "Unassigned bignum instance\n";
    else
    {
    	*this = *this - 1;
    }
    return tmp;
}

/****************************************************************/
/*			Sum assignment operator.		*/

bignum&  bignum::operator+=( const bignum& addend )

{
    *this = *this + addend;
    return *this;
}

/****************************************************************/
/*		Subtraction assignment operator.		*/

bignum&  bignum::operator-=( const bignum& subtrahend )

{
    *this = *this - subtrahend;
    return *this;
}

/****************************************************************/
/*		Multiplication assignment operator.		*/

bignum&  bignum::operator*=( const bignum& factor )

{
    *this = *this * factor;
    return *this;
}

/****************************************************************/
/*			 Division assignment operator.		*/

bignum&  bignum::operator/=( const bignum& factor )

{
    *this = *this / factor;
    return *this;
}

/****************************************************************/
/*			 Modulus assignment operator.		*/

bignum&  bignum::operator%=( const bignum& factor )

{
    *this = *this % factor;
    return *this;
}

/***********************************************************************/
/*		Returns "1" if *this == 0, returns "0" otherwise.      */

int  bignum::operator!() const
{
    int	   rslt = true;
    s1	   *tmp;

    if(digit->current != 0)	// Non-zero negative number.
    {
	 rslt=false;
    }
    else
    {
    	for(tmp=digit->nxt; tmp != digit; tmp=tmp->nxt)
	{
	    if(tmp->current != 0)
	    {
		rslt = false;
		break;
	    }
	}
    }
    return rslt;
}

/***********************************************************************/
/*			The "==" logic comparison			*/

int	 operator==(bignum n1, bignum n2)
{
    int	   rslt = true;
    s1	   *tmp1, *tmp2;

    n1.normalize();
    n2.normalize();

    if(n1.lgth != n2.lgth)
    {
	rslt = false;
    }
    else
    {
	tmp1 = n1.digit;
	tmp2 = n2.digit;

	do	//  Check every corresponding element.
	{
	    if(tmp1->current != tmp2->current)
	    {
		rslt = false;
		break;
	    }
	    tmp1 = tmp1->nxt;
	    tmp2 = tmp2->nxt;

	} while(tmp1 != n1.digit);
    }
    return rslt;
}

/***********************************************************************/
/*			The "!=" logic comparison			*/

int    operator!=(const bignum& n1, const bignum& n2)

{
    return !(n1 == n2);
}


/************************************************************************/
/*			The "<" logic comparison			*/

int	 operator<(const bignum& n1, const bignum& n2)
{
    int	   rslt = false;
    bignum difference;

    difference = n1 - n2;

    if(difference.digit->current) rslt = true;

    return rslt;
}

/************************************************************************/
/*			The "<=" logic comparison			*/

int	 operator<=(const bignum& n1, const bignum& n2)
{
    int	   rslt = true;
    bignum difference;

    difference = n2 - n1;

    if(difference.digit->current) rslt = false;

    return rslt;
}

/************************************************************************/
/*			The ">" logic comparison			*/

int	 operator>(const bignum& n1, const bignum& n2)
{
    int	   rslt = false;
    bignum difference;

    difference = n2 - n1;

    if(difference.digit->current) rslt = true;

    return rslt;
}

/************************************************************************/
/*			The ">=" logic comparison			*/

int	 operator>=(const bignum& n1, const bignum& n2)
{
    int	   rslt = true;
    bignum difference;

    difference = n1 - n2;

    if(difference.digit->current) rslt = false;

    return rslt;
}

/************************************************************************/
/*			Selects indexed "machine" digit.		*/

unsigned long	bignum::operator[](const int& index) const

{
    s1	*tmp;

    if(index >= lgth)
    {
	return( digit->current ? dgt_M_1 : 0 );
    }
    else if(index >= 0)
    {
	tmp = digit->prv;
	for(int i = 0; i < index; i++)
	{
	    tmp = tmp->prv;
	}
	return (tmp->current);
    }
    else
    {
	cerr << "Index out of range in \"operator[]\".\n";
	return 0;
    }
}

/***********************************************************************/
/*			"cout" support for bignum		       */

ostream& operator<<(ostream& stream, bignum nmbr)  // Output function.

{
    bignum	n_dgt;
    int		length = 0, sign = 0;
    char	*out_string;
    char_lst	*io_list, *c_start, *tmp;

    long	f, oflags = stream.flags();
    int		base, owidth;
    char	fill_char;

    // Get relevant conversion specifications from ostream.

    f = oflags & ios::basefield;	// Get base digits.
    switch(f)
    {
    	case ios::dec :	base = 10;
    		        break;
    	case ios::oct :	base = 8;
    		        break;
    	case ios::hex :	base = 16;
    		        break;
    	default :	base = 10;
    }

    owidth = stream.width(0);   
    fill_char = stream.fill();


    // Start the conversion.

    io_list = new char_lst(NULL);	// Create digit list.

    if(nmbr.digit->current)	// Negative number, add sign.
    {
	sign = 1;
	nmbr.negate();	// Quicker than "nmbr = -nmbr;"
    }

    do   // Division modulo "base" to get digits. Using do-while in order to get 0.
    {
	++length;
	tmp = new char_lst(io_list);
	n_dgt = nmbr % base;
	nmbr /= base;
	if(n_dgt == 0)
	{
	    tmp->io_digit = '0';
	}
	else if(n_dgt < 10)
	{
		 tmp->io_digit = n_dgt.digit->nxt->current + '0';
	}
	else if(f & ios::uppercase)
	{
		 tmp->io_digit = n_dgt.digit->nxt->current - 10 + 'A'; //Probably hex.
	}
	else	// Defaults to lower case for hex digits greater than 9.
	{
		 tmp->io_digit = n_dgt.digit->nxt->current - 10 + 'a'; //Probably hex.
	}
    } while(nmbr.lgth != 0);

    // We've finished the conversion, now for the other format amenities.

    if(oflags & ios::showbase)     switch(base)
    {
	case 8:  	  		 // Prepend a leading "0"
	    tmp = new char_lst(io_list);
	    tmp->io_digit = '0'; 
	    ++length;
	    break;

	case 16:                         // Prepend a leading "0x"
	    tmp = new char_lst(io_list);
	    tmp->io_digit = '0';
	    ++length;

	    tmp = new char_lst(io_list);
	    if(oflags & ios::uppercase)
	    {
		tmp->io_digit = 'X';
	    }
	    else
	    {
		tmp->io_digit = 'x';
            }
	    ++length;
	    break;
    }; // To kill the "if".

    if(sign)                            // Prepend a leading "-"
    {
	tmp = new char_lst(io_list);
	tmp->io_digit = '-';
	++length;
    }
    else if(oflags & ios::showpos)      // Prepend a leading "+"
    {
	tmp = new char_lst(io_list);
	tmp->io_digit = '+';
	++length;
    }

    if(owidth > length)	    // Need to justify and fill.
    {
        c_start = io_list;  // Points to where to insert fill characters.

	if(oflags & ios::left)  // Left justify
	{
	    c_start = io_list->prv;
	}
	else if(oflags & ios::internal)  // Internal justify
	{
	   if(sign || (oflags & ios::showpos)) // Skip over sign digit.
	   {
		c_start = c_start->nxt;
	   }
	   if((base == 8) && (ios::showbase))  // Skip over base digit "0".
	   {
		c_start = c_start->nxt;
	   }
	   else if((base == 16) && (ios::showbase))  // Skip over base digits "0x".
	   {
		c_start = c_start->nxt->nxt;
	   }
	}
	else	// The default = right justified.
	{
	    c_start = io_list;
	}

	for(int i=length; i < owidth; i++)  // Insert fill characters.
	{
	    tmp = new char_lst(c_start);
	    tmp->io_digit = fill_char;
	    ++length;
	}
    }

    out_string = new char[++length];	// Assign space for character string.

    //  Copy data structure into char string and delete uneeded space.

    for(int i=0; io_list->nxt != io_list; )
    {
	out_string[i++] = io_list->nxt->io_digit;
    	delete io_list->nxt;
    }
    out_string[i] = '\0';
    delete io_list;		// Purge used memory.

    cout << out_string;

    delete[] out_string;

    return stream;
}
/************************************************************************/
/*		Converts to output base - returns character string	*/

char*	bignum::output(int base) const

{
    unsigned	length = 0, sign = 0;
    int		i;
    bignum	nmbr, n_dgt;
    char	*out_string;
    char_lst	*io_list=NULL, *tmp;

    io_list = new char_lst(io_list);

    if(digit->current)	// Negative number, add sign.
    {
	sign = 1;
	nmbr = - *this;
    }
    else
    {
	nmbr = *this;
    }

    do   // Division modulo "base" to get digits. Using do-while in order to get 0.
    {
	++length;
	tmp = new char_lst(io_list);
	n_dgt = nmbr % base;
	nmbr /= base;
	if(n_dgt == 0)
	{
	    tmp->io_digit = '0';
	}
	else if(n_dgt < 10)
	{
	    tmp->io_digit = n_dgt.digit->nxt->current + '0';
	}
	else
	{
	    tmp->io_digit = n_dgt.digit->nxt->current - 10 + 'a'; //Probably hex.
	}
    } while(nmbr.lgth !=0);

    if(sign)
    {
	tmp = new char_lst(io_list);
	tmp->io_digit = '-';
	++length;
    }

    out_string = new char[++length];	// Assign space for character string.

   //  Copy data structure into char string and delete uneeded space.

    for(i=0; io_list->nxt != io_list; )
    {
	out_string[i++] = io_list->nxt->io_digit;
    	delete io_list->nxt;
    }
    out_string[i] = '\0';
    delete io_list;		// Purge used memory.

    return out_string;	// Return by value.
}

/**************************************************************************/
/*	              Bignumber exponentiation                            */

bignum	a_exp_b(const bignum& base, const bignum& exponent)

{
    bignum		modulus;	// Used to clamp magnitude.

    modulus.string_in(CLAMP);

    return(a_exp_b_mod_c(base, exponent, modulus));  // Return by value.
}


/**************************************************************************/
/*	              Bignumber exponentiation w/ modulus                 */

bignum	a_exp_b_mod_c(bignum base, const bignum& exponent, const bignum& modulus)

{
    unsigned long	word, bit;
    int			i;
    s1			*tmp;
    bignum		rslt = 1;

    if(exponent.digit->current)  // Negative exponent -> 0.
    {
	rslt = 0;
    }
    else
    {
	for(tmp = exponent.digit->prv; tmp != exponent.digit; tmp = tmp->prv)
	{
	    word = tmp->current;
	    for(i=0; i<bit_lgth; i++)
	    {
		bit = word & 0x01;
		if(bit)	{
		    (rslt *= base) %= modulus;
		}
		word = word >> 1;
		(base *= base) %= modulus;
	    }
	}
    }
    return(rslt);  // Return by value.
}


/************************************************************************/
/*			   Greatest Common Factor			*/

bignum	gcf(const bignum& n1, const bignum& n2)

{
    bignum	test_factor[2];
    int		a = 0;

    test_factor[a]  = n1;
    test_factor[!a] = n2;

// Euclid's algorithm.

    while(!!test_factor[a])   // Remainder = 0 is stopping condition.
    {
	test_factor[!a] %= test_factor[a];
	a = !a;
    }

    return test_factor[!a];  // Last remainder before zero.
}

/*************************************************************************/
/*			Constructor for "char_lst"			 */

char_lst::char_lst(char_lst *pntr)

{
    if(pntr == NULL)	{
	prv = this;
	nxt = this;
    }
    else 	{
	prv = pntr;
	nxt = pntr->nxt;
	nxt->prv = this;
	pntr->nxt = this;
    }
}

/*************************************************************************/

char_lst::~char_lst()

{
    prv->nxt = nxt;
    nxt->prv = prv;
}

/*************************************************************************/

struct	stack
{
    stack	*nxt;
    stack	*prv;
    bignum	stak_elm;
    int		depth;
    stack(stack*);
};

/*************************************************************************/

stack::stack(stack *pntr)

{
    if(pntr == NULL)	{
	prv = this;
	nxt = this;
    }
    else 	{
	prv = pntr;
	nxt = pntr->nxt;
	nxt->prv = this;
	pntr->nxt = this;
    }
}

/*************************************************************************/

bignum	pops(stack  *stk_ptr)

{
    stack	*stmp;
    bignum	rslt;

    stmp = stk_ptr->nxt;
    if(stmp != stk_ptr)	{
	rslt = stmp->stak_elm;

	stmp->prv->nxt = stmp->nxt;
	stmp->nxt->prv = stmp->prv;

	delete stmp;
    }
    else {
	rslt = NULL;
    }

    return(rslt);
}

void pushs(stack  *stk_ptr, bignum nmbr)

{
    stack	*stmp;

    stmp = new stack(stk_ptr);
    stmp->stak_elm = nmbr;
}

//  End of BIGNUM class definitions.


#define LINE_LGTH	133
main(argc, argv)

int	argc;
char	*argv[];

{
    bignum	arg1, arg2, arg3, rslt;
    int		i, sign, newstrg, test;
    int		io_base;

    char	buffer[LINE_LGTH];
    stack	*opstk = NULL, *stmp;

    opstk = new stack(opstk);

    io_base = dflt_base;		// Set I/O base to the default base.
    if(argc >= 3)
    {
    	if(strcmp(argv[1], "-b") == 0)
    	{
    	    io_base = atoi(argv[2]);
	}
    }	


    switch(io_base)
    {
		case  8:	cout.setf(ios::oct, ios::basefield);
				break;

		case 10:	cout.setf(ios::dec, ios::basefield);
    		                break;

		case 16:	cout.setf(ios::hex, ios::basefield);
				break;

		default :	fprintf(stderr, "Warning, only bases 8, 10, and 16 supported.  Defaulting to 10.\n");
				cout.setf(ios::dec, ios::basefield);
                                io_base = 10;	// Only bases 8, 10, and 16 are allowed.
    }


    while(gets(buffer) != NULL)	{
	newstrg = 1;
	for(i=0; 1; ++i)	{
	    switch(buffer[i])	{

	    case '0':
	    case '1':
	    case '2':
	    case '3':
	    case '4':
	    case '5':
	    case '6':
	    case '7':
	    case '8':
	    case '9':
		if(newstrg)	{
		    newstrg = 0;
		    sign = 0;
		    rslt = buffer[i] - '0';
		}
		else	{
		    rslt = io_base*rslt + (buffer[i] - '0');
		}
		break;

	    case 'a':
	    case 'b':
	    case 'c':
	    case 'd':
	    case 'e':
	    case 'f':
		if(newstrg)	{
		    newstrg = 0;
		    sign = 0;
		    rslt = buffer[i] - 'a' + 0xa;
		}
		else	{
		    rslt = io_base*rslt + (buffer[i] - 'a' + 0xa);
		}
		break;

	    case 'A':
	    case 'B':
	    case 'C':
	    case 'D':
	    case 'E':
	    case 'F':
		if(newstrg)	{
		    newstrg = 0;
		    sign = 0;
		    rslt = buffer[i] - 'A' + 0xa;
		}
		else	{
		    rslt = io_base*rslt + (buffer[i] - 'A' + 0xa);
		}
		break;

	    case ' ':
		if((!newstrg) && sign)	{
		    rslt = -rslt;
		}
		if(!newstrg)	{
		    pushs(opstk, rslt);
		    newstrg = 1;
		}

		break;

	    case '-':
		if((!newstrg) && sign)	{
		    rslt = -rslt;
		}

		if(!newstrg)	{
		    pushs(opstk, rslt);
		    newstrg = 1;
		}

		test = 	(('0' <= buffer[i+1]) && (buffer[i+1] <= '9')) ||
			(('a' <= buffer[i+1]) && (buffer[i+1] <= 'f')) ||
			(('A' <= buffer[i+1]) && (buffer[i+1] <= 'F'));

		if(test) {
		    newstrg = 0;
		    sign = 1;
		    rslt = 0;
		}
		else	{
		    if((arg2=pops(opstk)) == NULL)	{
//			fprintf(stderr, "stack empty.\n");
//			break;
		    }
		    if((arg1=pops(opstk)) == NULL)	{
//			fprintf(stderr, "stack empty.\n");
//			break;
		    }
		    rslt = arg1 - arg2;
		    cout << rslt << endl;
		    pushs(opstk, rslt);
		}
		break;

	    case '+':
		if((!newstrg) && sign)	{
		    rslt = -rslt;
		}
		if(!newstrg)	{
		    pushs(opstk, rslt);
		    newstrg = 1;
		}

		if((arg2=pops(opstk)) == NULL)	{
//		    fprintf(stderr, "stack empty.\n");
//		    break;
		}
		if((arg1=pops(opstk)) == NULL)	{
//		    fprintf(stderr, "stack empty.\n");
//		    break;
		}
		rslt = arg1 + arg2;
                cout << rslt << endl;
		pushs(opstk, rslt);
		break;

	    case '*':
		if((!newstrg) && sign)	{
		    rslt = -rslt;
		}

		if(!newstrg)	{
		    pushs(opstk, rslt);
		    newstrg = 1;
		}

		if((arg2=pops(opstk)) == NULL)	{
//		    fprintf(stderr, "stack empty.\n");
//		    break;
		}
		if((arg1=pops(opstk)) == NULL)	{
//		    fprintf(stderr, "stack empty.\n");
//		    break;
		}
		rslt = arg1 * arg2;
		cout << rslt << endl;
		pushs(opstk, rslt);

		break;

	    case '/':
		if((!newstrg) && sign)	{
		    rslt = -rslt;
		}

		if(!newstrg)	{
		    pushs(opstk, rslt);
		    newstrg = 1;
		}

		if((arg2=pops(opstk)) == NULL)	{
//		    fprintf(stderr, "stack empty.\n");
//		    break;
		}
		if((arg1=pops(opstk)) == NULL)	{
//		    fprintf(stderr, "stack empty.\n");
//		    break;
		}
		rslt = arg1 / arg2;
                cout << rslt << endl;
		pushs(opstk, rslt);

		break;

	    case '%':
		if((!newstrg) && sign)	{
		    rslt = -rslt;
		}

		if(!newstrg)	{
		    pushs(opstk, rslt);
		    newstrg = 1;
		}

		if((arg2=pops(opstk)) == NULL)	{
//		    fprintf(stderr, "stack empty.\n");
//		    break;
		}
		if((arg1=pops(opstk)) == NULL)	{
//		    fprintf(stderr, "stack empty.\n");
//		    break;
		}
		rslt = arg1 % arg2;
		cout << rslt << endl;
		pushs(opstk, rslt);

		break;

		 case '^':
		if((!newstrg) && sign)	{
		    rslt = -rslt;
		}

		if(!newstrg)	{
		    pushs(opstk, rslt);
		    newstrg = 1;
		}

		if((arg2=pops(opstk)) == NULL)	{
//		    fprintf(stderr, "stack empty.\n");
//		    break;
		}
		if((arg1=pops(opstk)) == NULL)	{
//		    fprintf(stderr, "stack empty.\n");
//		    break;
		}
		rslt = a_exp_b(arg1, arg2);
		cout << rslt << endl;
		pushs(opstk, rslt);

		break;

		 case '#':
		if((!newstrg) && sign)	{
		    rslt = -rslt;
		}

		if(!newstrg)	{
		    pushs(opstk, rslt);
		    newstrg = 1;
		}

		if((arg3=pops(opstk)) == NULL)	{
//		    fprintf(stderr, "stack empty.\n");
//		    break;
		}
		if((arg2=pops(opstk)) == NULL)	{
//		    fprintf(stderr, "stack empty.\n");
//		    break;
		}
		if((arg1=pops(opstk)) == NULL)	{
//		    fprintf(stderr, "stack empty.\n");
//		    break;
		}
		rslt = a_exp_b_mod_c(arg1, arg2, arg3);
		cout << rslt << endl;
		pushs(opstk, rslt);

		break;

	    case 'g':
		if((!newstrg) && sign)	{
		    rslt = -rslt;
		}

		if(!newstrg)	{
		    pushs(opstk, rslt);
		    newstrg = 1;
		}

		if((arg2=pops(opstk)) == NULL)	{
//		    fprintf(stderr, "stack empty.\n");
//		    break;
		}
		if((arg1=pops(opstk)) == NULL)	{
//		    fprintf(stderr, "stack empty.\n");
//		    break;
		}
		rslt = gcf(arg1, arg2);
		cout << rslt << endl;
		pushs(opstk, rslt);

		break;

	    case 'P':
		if((!newstrg) && sign)	{
		    rslt = -rslt;
		}

		if(!newstrg)	{
		    pushs(opstk, rslt);
		    newstrg = 1;
		}

		if((arg1=pops(opstk)) == NULL)	{
		}

		arg1.dump();
		pushs(opstk, arg1);

		break;

	    default:
		if((!newstrg) && sign)	{
		    rslt = -rslt;
		}

		if(!newstrg)	{
		    pushs(opstk, rslt);
		    newstrg = 1;
		}

	    }
	  if(buffer[i] == '\0')	break;
	}
    }
}

-----BEGIN PGP SIGNATURE-----
Version: 2.6.1

iQCVAwUBLwG0QcFJI0NoZp7xAQHrkQP+PZEChGf+MTr7LeJZZIBGWhOaAhJ2jnpb
rGJ29OaCzEM51XUxBaORPpz4dMy8qUYbBksM0VFzHwXGUnPTpOPYPgti8NA0qF/M
KmuFpJi3Mr+jYgpU5fPTecP4S72N8RExVCWOAdK2/6hWiI4jmPEjzZ6AEPOohI7O
+9LKBckSlro=
=07XN
-----END PGP SIGNATURE-----


