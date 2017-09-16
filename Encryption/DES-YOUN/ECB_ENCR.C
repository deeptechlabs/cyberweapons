/* ecb_encrypt.c */
/* Copyright (C) 1992 Eric Young - see COPYING for more details */
#include "des_local.h"
#include "spr.h"

int des_ecb_encrypt(input,output,ks,encrypt)
des_cblock *input;
des_cblock *output;
des_key_schedule ks;
int encrypt;
	{
	register ulong l0,l1;
	register uchar *in,*out;
	ulong ll[2];

	in=(uchar *)input;
	out=(uchar *)output;
	c2l(in,l0);
	c2l(in,l1);
	ll[0]=l0;
	ll[1]=l1;
	des_encrypt(ll,ll,ks,encrypt);
	l0=ll[0];
	l1=ll[1];
	l2c(l0,out);
	l2c(l1,out);
	return(0);
	}

/* The changes to this macro may help or hinder, depending on the
 * compiler and the achitecture.  gcc2 always seems to do well :-).  */
#ifdef ALT_ECB
#define D_ENCRYPT(L,R,S) \
	u=((R^s[S  ])<<2);	\
	t= R^s[S+1]; \
	t=((t>>2)+(t<<30)); \
	L^= \
	*(ulong *)(des_SP+0x0100+((t    )&0xfc))+ \
	*(ulong *)(des_SP+0x0300+((t>> 8)&0xfc))+ \
	*(ulong *)(des_SP+0x0500+((t>>16)&0xfc))+ \
	*(ulong *)(des_SP+0x0700+((t>>24)&0xfc))+ \
	*(ulong *)(des_SP+       ((u    )&0xfc))+ \
  	*(ulong *)(des_SP+0x0200+((u>> 8)&0xfc))+ \
  	*(ulong *)(des_SP+0x0400+((u>>16)&0xfc))+ \
 	*(ulong *)(des_SP+0x0600+((u>>24)&0xfc));
#else /* original version */
#define D_ENCRYPT(L,R,S)	\
	u=(R^s[S  ]); \
	t=R^s[S+1]; \
	t=((t>>4)+(t<<28)); \
	L^=	des_SPtrans[1][(t    )&0x3f]| \
		des_SPtrans[3][(t>> 8)&0x3f]| \
		des_SPtrans[5][(t>>16)&0x3f]| \
		des_SPtrans[7][(t>>24)&0x3f]| \
		des_SPtrans[0][(u    )&0x3f]| \
		des_SPtrans[2][(u>> 8)&0x3f]| \
		des_SPtrans[4][(u>>16)&0x3f]| \
		des_SPtrans[6][(u>>24)&0x3f];
#endif

	/* IP and FP
	 * The problem is more of a geometric problem that random bit fiddling.
	 0  1  2  3  4  5  6  7      62 54 46 38 30 22 14  6
	 8  9 10 11 12 13 14 15      60 52 44 36 28 20 12  4
        16 17 18 19 20 21 22 23      58 50 42 34 26 18 10  2
	24 25 26 27 28 29 30 31  to  56 48 40 32 24 16  8  0

	32 33 34 35 36 37 38 39      63 55 47 39 31 23 15  7
	40 41 42 43 44 45 46 47      61 53 45 37 29 21 13  5
	48 49 50 51 52 53 54 55      59 51 43 35 27 19 11  3
	56 57 58 59 60 61 62 63      57 49 41 33 25 17  9  1

	The output has been subject to swaps of the form
	0 1 -> 3 1 but the odd and even bits have been put into
	2 3    2 0 
	different words.  The main trick is to remember that
	t=((l>>size)^r)&(mask);
	r^=t;
	l^=(t<<size);
	can be used to swap and move bits between words.

	So l =  0  1  2  3  r = 16 17 18 19
	        4  5  6  7      20 21 22 23
	        8  9 10 11      24 25 26 27
	       12 13 14 15      28 29 30 31
	becomes (for size == 2 and mask == 0x3333)
	   t =   2^16  3^17 -- --   l =  0  1 16 17  r =  2  3 18 19
		 6^20  7^21 -- --        4  5 20 21       6  7 22 23
		10^24 11^25 -- --        8  9 24 25      10 11 24 25
                14^28 15^29 -- --       12 13 28 29      14 15 28 29

	Thanks for hints from Richard Outerbridge - he told me IP&FP
	could be done in 15 xor, 10 shifts and 5 ands.
	When I finally started to think of the problem in 2D
	I first got ~42 operations without xors.  When I remembered
	how to use xors :-) I got it to its final state.
	*/
#define PERM_OP(a,b,t,n,m) ((t)=((((a)>>(n))^(b))&(m)),\
	(b)^=(t),\
	(a)^=((t)<<(n)))

int des_encrypt(input,output,ks,encrypt)
ulong *input;
ulong *output;
des_key_schedule ks;
int encrypt;
	{
	register ulong l,r,t,u;
#ifdef ALT_ECB
	register uchar *des_SP=(uchar *)des_SPtrans;
#endif
	register int i;
	register ulong *s;

	l=input[0];
	r=input[1];

	/* do IP */
	PERM_OP(r,l,t, 4,0x0f0f0f0f);
	PERM_OP(l,r,t,16,0x0000ffff);
	PERM_OP(r,l,t, 2,0x33333333);
	PERM_OP(l,r,t, 8,0x00ff00ff);
	PERM_OP(r,l,t, 1,0x55555555);
	/* r and l are reversed - remember that :-) - fix
	 * it in the next step */

	/* Things have been modified so that the initial rotate is
	 * done outside the loop.  This required the 
	 * des_SPtrans values in sp.h to be rotated 1 bit to the right.
	 * One perl script later and things have a 5% speed up on a sparc2.
	 * Thanks to Richard Outerbridge <71755.204@CompuServe.COM>
	 * for pointing this out. */
	t=(r<<1)|(r>>31);
	r=(l<<1)|(l>>31); 
	l=t;

	s=(ulong *)ks;
	/* I don't know if it is worth the effort of loop unrolling the
	 * inner loop */
	if (encrypt)
		{
		for (i=0; i<32; i+=4)
			{
			D_ENCRYPT(l,r,i+0); /*  1 */
			D_ENCRYPT(r,l,i+2); /*  2 */
			}
		}
	else
		{
		for (i=30; i>0; i-=4)
			{
			D_ENCRYPT(l,r,i-0); /* 16 */
			D_ENCRYPT(r,l,i-2); /* 15 */
			}
		}
	l=(l>>1)|(l<<31);
	r=(r>>1)|(r<<31);

	/* swap l and r
	 * we will not do the swap so just remember they are
	 * reversed for the rest of the subroutine
	 * luckily FP fixes this problem :-) */

	PERM_OP(r,l,t, 1,0x55555555);
	PERM_OP(l,r,t, 8,0x00ff00ff);
	PERM_OP(r,l,t, 2,0x33333333);
	PERM_OP(l,r,t,16,0x0000ffff);
	PERM_OP(r,l,t, 4,0x0f0f0f0f);

	output[0]=l;
	output[1]=r;
	return(0);
	}

