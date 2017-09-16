/* lib/rsa/bn_mul.c */
/* Copyright (C) 1995 Eric Young (eay@mincom.oz.au)
 * All rights reserved.
 * 
 * This file is part of an SSL implementation written
 * by Eric Young (eay@mincom.oz.au).
 * The implementation was written so as to conform with Netscapes SSL
 * specification.  This library and applications are
 * FREE FOR COMMERCIAL AND NON-COMMERCIAL USE
 * as long as the following conditions are aheared to.
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.  If this code is used in a product,
 * Eric Young should be given attribution as the author of the parts used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Eric Young (eay@mincom.oz.au)
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <stdio.h>
#include "bn.h"

#ifdef IRIX_CC_BUG
unsigned long null(a)
unsigned long a;
	{
	return(a);
	}
#endif

#define			LBITS(a)	((a)&MASK2l)
#define			HBITS(a)	(((a)>>BITS4)&MASK2l)
#define			L2HBITS(a)	(((a)&MASK2l)<<BITS4)

/* r must be different to a and b */
int bn_mul(r, a, b)
BIGNUM *r;
BIGNUM *a;
BIGNUM *b;
	{
	int i,j;
	int max;
	BN_ULONG *ap,*bp,*rp;

	bn_zero(r);
	if ((a->top == 0) || (b->top == 0))
		{
		r->top=0;
		return(1);
		}

	max=(a->top+b->top+1);
	if (bn_expand(r,(max+1)*BITS2) == NULL) return(0);
	r->top=max;
	r->neg=a->neg^b->neg;
	bp=b->d;

	for (i=0; i<b->top; i++)
		{
#ifndef RSA_LLONG
#ifdef IRIX_CC_BUG
		unsigned long dummy;
#endif
		BN_ULONG bl,bh,c1;

		c1=0;
		rp= &(r->d[i]);
		ap=a->d;
		bh =*(bp++);
		bl=LBITS(bh);
		bh=HBITS(bh);

		for (j=a->top; j; j--)
			{
			register BN_ULONG l,h,m,m1;
			
			h= *(ap++);
			l =LBITS(h);
			h =HBITS(h);

			m =bh*l;		/* m2 = h(a)*l(b) */
			l =bl*l;		/* l = l(a)*l(b) */
			m1=bl*h;		/* m3= l(a)*h(b) */
			h =bh*h;		/* h = h(m)*h(b) */

			m+=m1;			/* m2 = m2 + m3 */
			if ((m&MASK2) < m1) h+=L2HBITS(1L);
			h+=HBITS(m);		/* H = h + h(M) */

			m1=L2HBITS(m);
			l+=m1; if ((l&MASK2) < m1) h++;

			/* non-multiply part */
			m1= *rp;
			l+=m1; if ((l&MASK2) < m1) h++;
			l+=c1; if ((l&MASK2) < c1) h++;
			c1=h&MASK2;
#ifdef IRIX_CC_BUG
			rp[0]=null(l&MASK2);
			rp++;
#else
			*(rp++)=l&MASK2;
#endif
			}
		*rp = c1;
#else
		BN_ULONG m,c1;
		BN_ULONG *lrp;

		m =*(bp++);
		rp= &(r->d[i]);
		j=a->top;
		lrp=rp+a->top;
		ap= a->d;
		c1=0;
		for (;;)
			{
			BN_ULLONG t;
#define	L	((BN_ULONG)t&MASK2)
#define	H	((BN_ULONG)(t>>BITS2)&MASK2)

#ifndef POINTER
#define mul(n)		t=(BN_ULLONG)m* ap[n] + rp[n] + c1; \
			rp[n]=L; \
			c1=H; \
			if (--j == 0) break;
#else
#define mul(n)		t=(BN_ULLONG)m* *(ap++) + *rp + c1; \
			*(rp++)=L; \
			c1=H; \
			if (--j == 0) break;
#endif

			mul(0); mul(1); mul(2); mul(3);
			mul(4); mul(5); mul(6); mul(7);
#ifndef POINTER
			ap+=8;
			rp+=8;
#endif
			}
		*lrp=c1;
#endif
		}
	bn_fix_top(r);
	return(1);
	}

