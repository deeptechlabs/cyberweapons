/* lib/rsa/bn.c */
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

#ifdef PROTO
static void bn_SUB(BIGNUM *r, BIGNUM *a, BIGNUM *b);
/*static void bn_fix_top(BIGNUM *a);*/
static BIGNUM *euclid(BIGNUM *a, BIGNUM *b);
static int bn_extended_euclid(BIGNUM * rd, BIGNUM * rx, BIGNUM * ry, BIGNUM * a, BIGNUM * b)
#else
static void bn_SUB();
/*static void bn_fix_top();*/
static BIGNUM *euclid();
static int bn_extended_euclid();
#endif

int bn_num_bits(a)
BIGNUM *a;
	{
	int i;
	BN_ULONG l;
	static char bits[256]={
		0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4,
		5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,
		6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
		6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
		7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
		7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
		7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
		7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
		8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
		8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
		8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
		8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
		8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
		8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
		8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
		8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
		};

	/* Added by Gary.Howland@systemics.com */
	if (a->top == 0) return(0);

	l=a->d[a->top-1];
	i=(a->top-1)*BITS2;
	if (l == 0)
		{
		fprintf(stderr,"BAD TOP VALUE\n");
		abort();
		}

#ifdef SIXTY_FOUR_BIT
	if (l & 0xffffffff00000000)
		{
		if (l & 0xffff000000000000)
			{
			if (l & 0xff00000000000000)
				{
				return(i+bits[l>>56]+56);
				}
			else	return(i+bits[l>>48]+48);
			}
		else
			{
			if (l & 0x0000ff0000000000)
				{
				return(i+bits[l>>40]+40);
				}
			else	return(i+bits[l>>32]+32);
			}
		}
	else
#endif
		{
#if defined(THIRTY_TWO_BIT) || defined(SIXTY_FOUR_BIT)
		if (l & 0xffff0000L)
			{
			if (l & 0xff000000L)
				return(i+bits[l>>24L]+24);
			else	return(i+bits[l>>16L]+16);
			}
		else
#endif
			{
			if (l & 0xff00L)
				return(i+bits[l>>8]+8);
			else	return(i+bits[l   ]  );
			}
		}
	}

void bn_free(a)
BIGNUM *a;
	{
	if (a == NULL) return;
	if (a->d != NULL) free(a->d);
	free(a);
	}

/*
static void bn_fix_top(a)
BIGNUM *a;
	{
	int i;
	BN_ULONG *l;

	l=a->d;
	for (i=a->top-1; i>0; i--)
		if (l[i]) break;
	a->top=i+1;
	}
*/

BIGNUM *bn_new()
	{
	BIGNUM *ret;
	BN_ULONG *p;

	ret=(BIGNUM *)malloc(sizeof(BIGNUM));
	if (ret == NULL)
		return NULL;
	ret->top=0;
	ret->neg=0;
	ret->max=(DEFAULT_BITS/BITS2);
	p=(BN_ULONG *)malloc(sizeof(BN_ULONG)*(ret->max+1));
	if (p == NULL)
		return NULL;
	ret->d=p;

	memset(p,0,(ret->max+1)*sizeof(p[0]));
	return(ret);
	}

BIGNUM *bn_expand(b, bits)
BIGNUM *b;
int bits;
	{
	BN_ULONG *p;
	register int n;

/*	if (b == NULL)
		{ RSAerr(RSA_F_BN_EXPAND,RSA_R_NULL_ARG); return(NULL); }*/
	while (bits > b->max*BITS2)
		{
		n=((bits+BITS2-1)/BITS2)*2;
		p=b->d=(BN_ULONG *)realloc(b->d,sizeof(BN_ULONG)*n+1);
		if (p == NULL)
			return NULL;
		memset(&(p[b->max]),0,((n+1)-b->max)*sizeof(p[0]));
/*		for (i=b->max; i<(n+1); i++)
			p[i]=0;*/
		b->max=n;
		}
	return(b);
	}

BIGNUM *bn_dup(a)
BIGNUM *a;
	{
	BIGNUM *r;

	r=bn_new();
	if (r == NULL) return(NULL);
	return((BIGNUM *)bn_copy(r,a));
	}

BIGNUM *bn_copy(a, b)
BIGNUM *a;
BIGNUM *b;
	{
/*	int i;*/

	if (bn_expand(a,b->top*BITS2) == NULL) return(NULL);
	memcpy(a->d,b->d,sizeof(b->d[0])*b->top);
	memset(&(a->d[b->top]),0,sizeof(a->d[0])*(a->max-b->top));
/*	for (i=0; i<b->top; i++)
		a->d[i]=b->d[i];
	for (;i<a->max; i++)
		a->d[i]=0;*/
	a->top=b->top;
	a->neg=b->neg;
	return(a);
	}

void bn_zero(a)
BIGNUM *a;
	{
	memset(a->d,0,a->max*sizeof(a->d[0]));
	a->top=0;
	a->neg=0;
	}

int bn_one(a)
BIGNUM *a;
	{
	if (bn_expand(a,1) == NULL) return(0);
	memset(a->d,0,a->max);
	a->d[0]=1;
	a->top=1;
	a->neg=0;
	return(1);
	}

int bn_set_word(a,w)
BIGNUM *a;
unsigned long w;
	{
	if (bn_expand(a,sizeof(unsigned long)*8) == NULL) return(0);
	memset(a->d,0,a->max);

	a->d[0]=w;
	a->top=1;
	a->neg=0;
	return(1);
	}

/* ignore negative */
BIGNUM *bn_bin2bn(len, s, ret)
int len;
unsigned char *s;
BIGNUM *ret;
	{
	unsigned int i,m;
	unsigned int n;
	BN_ULONG l;

	if (ret == NULL) ret=bn_new();
	if (ret == NULL) return(NULL);
	l=0;
	n=len;
	if (n == 0)
		{
		ret->top=0;
		return(ret);
		}
	if (bn_expand(ret,(int)n*8) == NULL)
		return(NULL);
	i=((n-1)/BYTES)+1;
	m=((n-1)%(BYTES));
	ret->top=i;
	while (n-- > 0)
		{
		l=(l<<8)| *(s++);
		if (m-- == 0)
			{
			ret->d[--i]=l;
			l=0;
			m=BYTES-1;
			}
		}
	/* need to call this due to clear byte at top if avoiding
	 * having the top bit set (-ve number) */
	bn_fix_top(ret);
	return(ret);
	}

void bn_print(fp, a)
FILE *fp;
BIGNUM *a;
	{
	int i,j,v,z=0;
	static char *hex="0123456789ABCDEF";

	if (a->neg) fputc('-',fp);
	if (a->top == 0) fputc('0',fp);
	for (i=a->top-1; i >=0; i--)
		{
		for (j=BITS2-4; j >= 0; j-=4)
			{
			/* strip leading zeros */
			v=(a->d[i]>>j)&0x0f;
			if (z || (v != 0))
				{
				fputc(hex[v],fp);
				z=1;
				}
			}
		}
	}

/* ignore negative */
int bn_bn2bin(a, to)
BIGNUM *a;
unsigned char *to;
	{
	int n,i;
	BN_ULONG l;

	n=i=bn_num_bytes(a);
	while (i-- > 0)
		{
		l=a->d[i/BYTES];
		*(to++)=(unsigned char)(l>>(8*(i%BYTES)))&0xff;
		}
	return(n);
	}

/* r can == a or b */
int bn_add(r, a, b)
BIGNUM *r;
BIGNUM *a;
BIGNUM *b;
	{
	register int i;
	int max,min;
	BN_ULONG *ap,*bp,*rp,carry,t1,t2;
	BIGNUM *tmp;

	/*  a +  b	a+b
	 *  a + -b	a-b
	 * -a +  b	b-a
	 * -a + -b	-(a+b)
	 */
	if (a->neg ^ b->neg)
		{
		if (a->neg)
			{ a->neg=0; i=bn_sub(r,b,a); if (a != r) a->neg=1; }
		else
			{ b->neg=0; i=bn_sub(r,a,b); if (b != r) b->neg=1; }
		return(i);
		}
	if (a->neg) /* both are neg */
		{
		a->neg=0; b->neg=0; i=bn_add(r,a,b);
		if (a != r) a->neg=1;
		if (b != r) b->neg=1;
		return(i);
		}
	if (a->top < b->top)
		{ tmp=a; a=b; b=tmp; }
		
	max=a->top;
	min=b->top;
	if (bn_expand(r,(max+1)*BITS2) == NULL) return(0);
	r->top=max;
	r->neg=0;

	ap=a->d;
	bp=b->d;
	rp=r->d;
	carry=0;
	for (i=0; i<min; i++)
		{
		t1= *(ap++);
		t2= *(bp++);
		if (carry)
			{
			carry=(t2 >= ((~t1)&MASK2));
			t2=(t1+t2+1)&MASK2;
			}
		else
			{
			t2=(t1+t2)&MASK2;
			carry=(t2 < t1);
			}
		*(rp++)=t2;
		}
	if (carry)
		{
		while (i < max)
			{
			t1= *(ap++);
			t2=(t1+1)&MASK2;
			*(rp++)=t2;
			carry=(t2 < t1);
			i++;
			if (!carry) break;
			}
		if ((i >= max) && carry)
			{
			*(rp++)=1;
			r->top++;
			}
		}
	for (; i<max; i++)
		*(rp++)= *(ap++);
	memcpy(rp,ap,sizeof(*ap)*(max-i));
	return(1);
	}

int bn_Ucmp(a, b)
BIGNUM *a;
BIGNUM *b;
	{
	int i;
	BN_ULONG t1,t2,*ap,*bp;

	i=a->top-b->top;
	if (i != 0) return(i);
	ap=a->d;
	bp=b->d;
	for (i=a->top-1; i>=0; i--)
		{
		t1=ap[i];
		t2=bp[i];
		if (t1 > t2) return(1);
		if (t1 < t2) return(-1);
		}
	return(0);
	}

int bn_cmp(a, b)
BIGNUM *a;
BIGNUM *b;
	{
	int i;
	int gt,lt;
	BN_ULONG t1,t2;

	if (a->neg != b->neg)
		{
		if (a->neg)
			return(-1);
		else	return(1);
		}
	if (a->neg == 0)
		{ gt=1; lt=-1; }
	else	{ gt=-1; lt=1; }

	if (a->top > b->top) return(gt);
	if (a->top < b->top) return(lt);
	for (i=a->top-1; i>=0; i--)
		{
		t1=a->d[i];
		t2=b->d[i];
		if (t1 > t2) return(gt);
		if (t1 < t2) return(lt);
		}
	return(0);
	}

static void bn_SUB(r, a, b)
BIGNUM *r;
BIGNUM *a;
BIGNUM *b;
	{
	int max,min;
	register BN_ULONG t1,t2,*ap,*bp,*rp;
	int i,carry;
#if defined(IRIX_CC_BUG) && !defined(LINT)
	int dummy;
#endif

	max=a->top;
	min=b->top;
	ap=a->d;
	bp=b->d;
	rp=r->d;

	carry=0;
	for (i=0; i<min; i++)
		{
		t1= *(ap++);
		t2= *(bp++);
		if (carry)
			{
			carry=(t1 <= t2);
			t1=(t1-t2-1);
			}
		else
			{
			carry=(t1 < t2);
			t1=(t1-t2);
			}
#if defined(IRIX_CC_BUG) && !defined(LINT)
		dummy=t1;
#endif
		*(rp++)=t1&MASK2;
		}
	if (carry) /* subtracted */
		{
		while (i < max)
			{
			i++;
			t1= *(ap++);
			t2=(t1-1)&MASK2;
			*(rp++)=t2;
			if (t1 > t2) break;
			}
		}
	memcpy(rp,ap,sizeof(*rp)*(max-i));
/*	for (; i<max; i++)
		*(rp++)=*(ap++);*/

	r->top=max;
	bn_fix_top(r);
	}

int bn_sub(r, a, b)
BIGNUM *r;
BIGNUM *a;
BIGNUM *b;
	{
	int max,i;

	/*  a -  b	a-b
	 *  a - -b	a+b
	 * -a -  b	-(a+b)
	 * -a - -b	b-a
	 */
	if (a->neg)
		{
		if (b->neg)
			{
			a->neg=b->neg=0;
			i=bn_sub(r,b,a);
			if (a != r) a->neg=1;
			if (b != r) b->neg=1;
			}
		else
			{
			a->neg=0;
			i=bn_add(r,a,b);
			r->neg=a->neg=1;
			}
		return(i);
		}
	else
		{
		if (b->neg)
			{
			b->neg=0;
			i=bn_add(r,a,b);
			if (r != b) b->neg=1;
			return(i);
			}
		}

	max=(a->top > b->top)?a->top:b->top;
	if (bn_cmp(a,b) < 0)
		{
		if (bn_expand(r,max*BITS2) == NULL) return(0);
		bn_SUB(r,b,a);
		r->neg=1;
		}
	else
		{
		if (bn_expand(r,max*BITS2) == NULL) return(0);
		bn_SUB(r,a,b);
		r->neg=0;
		}
	return(1);
	}

int bn_lshift1(r, a)
BIGNUM *r;
BIGNUM *a;
	{
	register BN_ULONG *ap,*rp,t,c;
	int i;

	if (r != a)
		{
		r->neg=a->neg;
		if (bn_expand(r,(a->top+1)*BITS2) == NULL) return(0);
		r->top=a->top;
		}
	else
		{
		if (bn_expand(r,(a->top+1)*BITS2) == NULL) return(0);
		}
	ap=a->d;
	rp=r->d;
	c=0;
	for (i=0; i<a->top; i++)
		{
		t= *(ap++);
		*(rp++)=((t<<1)|c)&MASK2;
		c=(t & TBIT)?1:0;
		}
	if (c)
		{
		*rp=1;
		r->top++;
		}
	return(1);
	}

int bn_rshift1(r, a)
BIGNUM *r;
BIGNUM *a;
	{
	BN_ULONG *ap,*rp,t,c;
	int i;

	if (bn_is_zero(a))
		{
		bn_zero(r);
		return(1);
		}
	if (a != r)
		{
		if (bn_expand(r,a->top*BITS2) == NULL) return(0);
		r->top=a->top;
		r->neg=a->neg;
		}
	ap=a->d;
	rp=r->d;
	c=0;
	for (i=a->top-1; i>=0; i--)
		{
		t=ap[i];
		rp[i]=((t>>1)&MASK2)|c;
		c=(t&1)?TBIT:0;
		}
	bn_fix_top(r);
	return(1);
	}

int bn_lshift(r, a, n)
BIGNUM *r;
BIGNUM *a;
int n;
	{
	int i,nw,lb,rb;
	BN_ULONG *t,*f;
	BN_ULONG l;

	r->neg=a->neg;
	if (bn_expand(r,(a->top*BITS2)+n) == NULL) return(0);
	nw=n/BITS2;
	lb=n%BITS2;
	rb=BITS2-lb;
	f=a->d;
	t=r->d;
	t[a->top+nw]=0;
	if (lb == 0)
		for (i=a->top-1; i>=0; i--)
			t[nw+i]=f[i];
	else
		for (i=a->top-1; i>=0; i--)
			{
			l=f[i];
			t[nw+i+1]|=(l>>rb)&MASK2;
			t[nw+i]=(l<<lb)&MASK2;
			}
	memset(t,0,nw*sizeof(t[0]));
/*	for (i=0; i<nw; i++)
		t[i]=0;*/
	r->top=a->top+nw+1;
	bn_fix_top(r);
	return(1);
	}

int bn_rshift(r, a, n)
BIGNUM *r;
BIGNUM *a;
int n;
	{
	int i,nw,lb,rb;
	BN_ULONG *t,*f;
	BN_ULONG l;

	r->neg=a->neg;
	nw=n/BITS2;
	rb=n%BITS2;
	lb=BITS2-rb;
	if (nw > a->top)
		{
		bn_zero(r);
		return(1);
		}
	if (bn_expand(r,(a->top-nw+1)*BITS2) == NULL) return(0);
	f=a->d;
	t=r->d;
	if (rb == 0)
		for (i=nw; i<a->top; i++)
			t[i-nw]=f[i];
	else
		{
		l=f[nw];
		for (i=nw; i<a->top; i++)
			{
			t[i-nw] =(l>>rb)&MASK2;
			l=f[i+1];
			t[i-nw]|=(l<<lb)&MASK2;
			}
		}
	r->top=a->top-nw;
	t[r->top]=0;
	bn_fix_top(r);
	return(1);
	}

int bn_clear_bit(a, n)
BIGNUM *a;
int n;
	{
	int i,j;

	i=n/BITS2;
	j=n%BITS2;
	if (a->top <= i) return(0);

	return(a->d[i]&(~(1L<<j)));
	}

int bn_is_bit_set(a, n)
BIGNUM *a;
int n;
	{
	int i,j;

	i=n/BITS2;
	j=n%BITS2;
	if (a->top <= i) return(0);
	return((a->d[i]&(1L<<j))?1:0);
	}

/* rem != m */
int bn_mod(rem, m, d)
BIGNUM *rem;
BIGNUM *m;
BIGNUM *d;
	{
	int i,nm,nd,tos;
	BIGNUM *dv;

	if (bn_Ucmp(m,d) < 0)
		return((bn_copy(rem,m) == NULL)?0:1);
	tos=bn_get_tos();
	dv=bn_get_reg();
	if (dv == NULL) return(0);

	if (!bn_copy(rem,m)) return(0);

	nm=bn_num_bits(rem);
	nd=bn_num_bits(d);
	if (!bn_lshift(dv,d,nm-nd)) return(0);
	for (i=nm-nd; i>=0; i--)
		{
		if (bn_cmp(rem,dv) >= 0)
			{
			if (!bn_sub(rem,rem,dv)) return(0);
			}
		if (!bn_rshift1(dv,dv)) return(0);
		}
	bn_set_tos(tos);
	return(1);
	}

static int mod_init=1;
static int mod_bits,mod_shift;
static BIGNUM *mod_value;
static BIGNUM *mod_shifts[BITS2];
static BN_ULONG *mod_shiftp[BITS2];
static int mod_top[BITS2];

int bn_mod2_init(d, max_bits)
BIGNUM *d;
int max_bits;
	{
	int i;

	if (mod_init)
		{
		mod_init=0;
		for (i=0; i<BITS2; i++)
			{
			mod_shifts[i]=bn_new();
			if (mod_shifts[i] == NULL)
				{ return(0); }
			}
		mod_value=bn_new();
		if (mod_value == NULL)
			{ return(0); }
		}
	if (bn_copy(mod_value,d) == NULL) return(0);
	mod_bits=bn_num_bits(d);
	mod_shift=max_bits-mod_bits;

	if (!bn_lshift(mod_shifts[0],d,mod_shift)) return(0);
	for (i=1; i<BITS2; i++)
		if (!bn_rshift1(mod_shifts[i],mod_shifts[i-1])) return(0);
	for (i=0; i<BITS2; i++)
		{
		mod_shiftp[i]=mod_shifts[i]->d;
		mod_top[i]=mod_shifts[i]->top;
		}
	return(1);
	}

/* don't use :-( */
int bn_mod2(ret, m, d)
BIGNUM *ret;
BIGNUM *m;
BIGNUM *d;
	{
	int i,j,nm,nd,x;
	int w;

	if (bn_copy(ret,m) == NULL) return(0);
	if (bn_cmp(m,mod_value) < 0)
		return(1);
	nm=bn_num_bits(m);
	nd=mod_bits;
	i=nm-nd;

	j=mod_shift-i;	/* take off what we are shifted,
			 * how far do we need to go back */
	w=j/BITS2;	/* number of words to jump back */
	x=j%BITS2;	/* which shift to start on */

	if (w != 0)
		for (i=0; i<BITS2; i++) 
			{
			j=w+(x>i);
			mod_shifts[i]->top-=j;
			mod_shifts[i]->d+=j;
			}
	
	for (i=nm-nd; i>=0; i--)
		{
		if (bn_cmp(ret,mod_shifts[x]) >= 0)
			{
			if (!bn_sub(ret,ret,mod_shifts[x])) return(0);
			}

		mod_shifts[x]->top--;
		mod_shifts[x]->d++;
		x=(x+1)%BITS2;
		}
	for (i=0; i<BITS2; i++)
		{
		mod_shifts[i]->d=mod_shiftp[i];
		mod_shifts[i]->top=mod_top[i];
		}
#ifdef LINT
	d->d[0]=d->d[0];
#endif
	return(1);
	}

int bn_div(dv, rem, m, d)
BIGNUM *dv;
BIGNUM *rem;
BIGNUM *m;
BIGNUM *d;
	{
	int i,nm,nd;
	BIGNUM *D;
	int tos;

	/* Check for divide by zero */
	if (bn_is_zero(d))
		return NULL;

	if (bn_cmp(m,d) < 0)
		{
		if (rem != NULL)
			{ if (bn_copy(rem,m) == NULL) return(0); }
		if (dv != NULL) bn_zero(dv);
		return(1);
		}

	tos=bn_get_tos();
	D=bn_get_reg();
	if (dv == NULL) dv=bn_get_reg();
	if (rem == NULL) rem=bn_get_reg();
	if ((D == NULL) || (dv == NULL) || (rem == NULL))
		return(0);

	nd=bn_num_bits(d);
	nm=bn_num_bits(m);
	if (bn_copy(D,d) == NULL) return(0);
	if (bn_copy(rem,m) == NULL) return(0);

	/* The next 2 are needed so we can do a dv->d[0]|=1 later
	 * since bn_lshift1 will only work once there is a value :-) */
	bn_zero(dv);
	dv->top=1;

	if (!bn_lshift(D,D,nm-nd)) return(0);
	for (i=nm-nd; i>=0; i--)
		{
		if (!bn_lshift1(dv,dv)) return(0);
		if (bn_cmp(rem,D) >= 0)
			{
			dv->d[0]|=1;
			if (!bn_sub(rem,rem,D)) return(0);
			}
/* CAN IMPROVE */
		if (!bn_rshift1(D,D)) return(0);
		}
	dv->neg=m->neg^d->neg;
	bn_set_tos(tos);
	return(1);
	}

BN_ULONG bn_mod_word(a, w)
BIGNUM *a;
unsigned long w;
	{
	BN_ULONG ret;
	int i;

	ret=0;
	for (i=a->top-1; i>=0; i--)
		{
#ifndef RSA_LLONG
		ret=((ret<<BITS4)|((a->d[i]>>BITS4)&MASK2l))%w;
		ret=((ret<<BITS4)|(a->d[i]&MASK2l))%w;
#else
		ret=(((BN_ULLONG)ret<<BITS2)|a->d[i])%w;
#endif
		}
	return(ret);
	}

int bn_add_word(a, w)
BIGNUM *a;
unsigned long w;
	{
	BN_ULONG l;
	int i;

	if (bn_expand(a,a->top*BITS2+1) == NULL) return(0);
	i=0;
	for (;;)
		{
		l=(a->d[i]+w)&MASK2;
		a->d[i]=l;
		if (w > l)
			w=1;
		else
			break;
		i++;
		}
	if (i >= a->top)
		a->top++;
	return(1);
	}


int bn_mul_mod(ret, a, b, m)
BIGNUM *ret;
BIGNUM *a;
BIGNUM *b;
BIGNUM *m;
	{
	BIGNUM *t;
	int tos,r=1;

	tos=bn_get_tos();
	t=bn_get_reg();
	if (t == NULL) return(0);
	if (!bn_mul(t,a,b)) { r=0; goto err; }
	if (!bn_mod(ret,t,m)) { r=0; goto err; }
err:
	bn_set_tos(tos);
	return(r);
	}

#ifndef RECP_MUL_MOD
/* this one works */
int bn_mod_exp(r,a,p,m)
BIGNUM *r,*a,*p,*m;
	{
	int tos,i,bits;
	BIGNUM *v=NULL,*tmp=NULL;

	tos=bn_get_tos();
	if (v == NULL) v=bn_get_reg();
	if (tmp == NULL) tmp=bn_get_reg();
	if ((v == NULL) || (tmp == NULL)) goto err;
	if (bn_copy(v,a) == NULL) goto err;
	bits=bn_num_bits(p);

	if (p->d[0]&1)
		{ if (bn_copy(r,a) == NULL) goto err; }
	else	{ if (bn_one(r) == NULL) goto err; }

	if (!bn_mod2_init(m,m->top*3*BITS2)) goto err;
	for (i=1; i<bits; i++)
		{
		if (!bn_mul(tmp,v,v)) goto err;
		if (!bn_mod2(v,tmp,m)) goto err;
		if (bn_is_bit_set(p,i))
			{
			if (!bn_mul(tmp,r,v)) goto err;
			if (!bn_mod2(r,tmp,m)) goto err;
			}
		}
	bn_set_tos(tos);
	return(1);
err:
	bn_set_tos(tos);
	return(0);
	}

#else
int bn_mod_exp(r, a, p, m)
BIGNUM *r;
BIGNUM *a;
BIGNUM *p;
BIGNUM *m;
	{
	int tos,nb,i,bits;
	BIGNUM *v=NULL,*tmp=NULL;
	BIGNUM *d=NULL;

	tos=bn_get_tos();
	if (v == NULL) v=bn_get_reg();
	if (tmp == NULL) tmp=bn_get_reg();
	if (d == NULL) d=bn_get_reg();
	if ((v == NULL) || (tmp == NULL) || (d == NULL)) goto err;
	if (!bn_mod(v,a,m)) goto err;
	bits=bn_num_bits(p);

	if (p->d[0]&1)
		{ if (!bn_mod(r,a,m)) goto err; }
	else	{ if (!bn_one(r)) goto err; }

	nb=bn_reciprical(d,m);
	if (nb == -1) goto err;
	for (i=1; i<bits; i++)
		{
		if (!bn_modmul_recip(v,v,v,m,d,nb)) goto err;
		if (bn_is_bit_set(p,i))
			{ if (!bn_modmul_recip(r,r,v,m,d,nb)) goto err; }
		}
	bn_set_tos(tos);
	return(1);
err:
	bn_set_tos(tos);
	return(0);
	}
#endif

int bn_modmul_recip(r, x, y, m, i, nb)
BIGNUM *r;
BIGNUM *x;
BIGNUM *y;
BIGNUM *m;
BIGNUM *i;
int nb;
	{
	int tos,j;
	BIGNUM *a,*b,*c,*d;

	tos=bn_get_tos();
	a=bn_get_reg();
	b=bn_get_reg();
	c=bn_get_reg();
	d=bn_get_reg();
	if ((a == NULL) || (b == NULL) || (c == NULL) || (d == NULL))
		goto err;

	if (!bn_mul(a,x,y)) goto err;
	if (!bn_rshift(d,a,nb-1)) goto err;
	if (!bn_mul(b,d,i)) goto err;
	if (!bn_rshift(c,b,nb-1)) goto err;
	if (!bn_mul(b,m,c)) goto err;
	if (!bn_sub(r,a,b)) goto err;
	j=0;
	while (bn_cmp(r,m) >= 0)
		{
		if (j++ > 2)
			goto err;
		if (!bn_sub(r,r,m))
			goto err;
		}

	bn_set_tos(tos);
	return(1);
err:
	bn_set_tos(tos);
	return(0);
	}

int bn_reciprical(r, m)
BIGNUM *r;
BIGNUM *m;
	{
	int nm,tos;
	BIGNUM *t;

	tos=bn_get_tos();
	t=bn_get_reg();
	if (t == NULL) goto err;

	if (!bn_one(t)) goto err;
	nm=bn_num_bits(m);
	if (!bn_lshift(t,t,nm*2)) goto err;

	if (!bn_div(r,NULL,t,m)) goto err;
	bn_set_tos(tos);
	return(nm+1);
err:
	bn_set_tos(tos);
	return(-1);
	}

/*
 *	Warning - Non re-entrant
 */
char *bn_bn2ascii(a)
BIGNUM *a;
	{
	int i,j,v,z=0;
	static char *hex="0123456789ABCDEF";
	static char buf[1024];
	char *p=buf;

	if ((a->top*BYTES*2) > sizeof(buf)+2)
		return("buffer too small in bn_bn2ascii");
	if (a->neg) *(p++)='-';
	if (a->top == 0) *(p++)='0';
	for (i=a->top-1; i >=0; i--)
		{
		for (j=BITS2-4; j >= 0; j-=4)
			{
			/* strip leading zeros */
			v=(a->d[i]>>j)&0x0f;
			if (z || (v != 0))
				{
				*(p++)=hex[v];
				z=1;
				}
			}
		}
	return(buf);
	}

int bn_gcd(r,in_a,in_b)
BIGNUM *r,*in_a,*in_b;
	{
	BIGNUM *a,*b,*t;
	int tos,ret=0;

	tos=bn_get_tos();
	a=bn_get_reg();
	b=bn_get_reg();
	if ((a == NULL) || (b == NULL)) goto err;

	if (!bn_copy(a,in_a)) goto err;
	if (!bn_copy(b,in_b)) goto err;

	if (bn_cmp(a,b) < 0) { t=a; a=b; b=t; }
	t=euclid(a,b);
	if (t == NULL) goto err;

	r=bn_copy(r,t);
	ret=1;
err:
	bn_set_tos(tos);
	return(ret);
	}


static BIGNUM *euclid(a,b)
BIGNUM *a,*b;
	{
	BIGNUM *t;
	int shifts=0;

	for (;;)
		{
		if (bn_is_zero(b))
			break;

		if ((a->d[0]&1))	/* a is odd */
			{
			if (b->d[0]&1)  /* b is odd */
				{
				if (!bn_sub(a,a,b)) goto err;
				if (!bn_rshift1(a,a)) goto err;
				if (bn_cmp(a,b) < 0)
					{ t=a; a=b; b=t; }
				}
			else		/* a odd - b even */
				{
				if (!bn_rshift1(b,b)) goto err;
				if (bn_cmp(a,b) < 0)
					{ t=a; a=b; b=t; }
				}
			}
		else			/* a is even */
			{
			if (b->d[0]&1)	/* b id odd */
				{
				if (!bn_rshift1(a,a)) goto err;
				if (bn_cmp(a,b) < 0)
					{ t=a; a=b; b=t; }
				}
			else		/* a even - b even */
				{
				if (!bn_rshift1(a,a)) goto err;
				if (!bn_rshift1(b,b)) goto err;
				shifts++;
				}
			}
		}
	if (shifts)
		{
		if (!bn_lshift(a,a,shifts)) goto err;
		}
	return(a);
err:
	return(NULL);
	}


/* solves ax == 1 (mod n) */
int bn_inverse_modn(r, in_a, in_n)
BIGNUM *r;
BIGNUM *in_a;
BIGNUM *in_n;
	{
	BIGNUM *t,*d,*x1,*y1;
	BIGNUM *n,*a;
	int tos,ret=0;

	t=bn_new();

	tos=bn_get_tos();
	d=bn_get_reg();
	x1=bn_get_reg();
	y1=bn_get_reg();
	a=bn_get_reg();
	n=bn_get_reg();
	if ((d == NULL) || (x1 == NULL) || (y1 == NULL) || (a == NULL) || (n == NULL))
		goto err;

	if (!bn_copy(a,in_a)) goto err;
	if (!bn_copy(n,in_n)) goto err;

	if (!bn_extended_euclid(&d,&x1,&y1,n,a)) goto err;

	if (y1->neg)
		{
		if (!bn_add(y1,y1,n)) goto err;
		}

	if (bn_is_one(d))
		{ if (!bn_mod(t,y1,n)) goto err; }
	else
		{ goto err; }

	r=bn_copy(r,t);
	ret=1;
err:
	bn_set_tos(tos);
	return(ret);
	}

static int bn_extended_euclid(rd, rx, ry, a, b)
BIGNUM **rd;
BIGNUM **rx;
BIGNUM **ry;
BIGNUM *a;
BIGNUM *b;
	{
	BIGNUM *A,*B,*tmp;
	int tos=bn_get_tos();

	if (bn_is_zero(b))
		{
		if (bn_copy(*rd,a) == NULL) goto err;
		if (!bn_one(*rx)) goto err;
		bn_zero(*ry);
		return(1);
		}

	A=bn_get_reg();
	if (A == NULL) goto err;
	if (!bn_mod(A,a,b)) goto err;

	if (!bn_extended_euclid(rd,rx,ry,b,A))
		goto err;
	tmp= *rx;
	*rx= *ry;
	if (!bn_div(A,NULL,a,b)) goto err;

	B=bn_get_reg();
	if (B == NULL) goto err;

	if (!bn_mul(B,*ry,A)) goto err;
	if (!bn_sub(A,tmp,B)) goto err;
	if (bn_copy(tmp,A) == NULL) goto err;
	*ry=tmp;

	bn_set_tos(tos);
	return(1);
err:
	bn_set_tos(tos);
	return(0);
	}
