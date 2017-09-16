/* lib/rsa/bn.h */
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

#ifndef HEADER_BN_H
#define HEADER_BN_H

#ifndef _Windows
#define RSA_LLONG
#endif
#define RECP_MUL_MOD

/* Only one for the following should be defined */
#undef SIXTY_FOUR_BIT
#define THIRTY_TWO_BIT
#undef SIXTEEN_BIT

/* assuming long is 64bit - this is the DEC Alpha */
#ifdef SIXTY_FOUR_BIT
#define BN_ULLONG	unsigned long long
#define BN_ULONG	unsigned long
#define BN_LONG		long
#define BITS	128
#define BYTES	8
#define BITS2	64
#define BITS4	32
#define MASK2	(0xffffffffffffffffL)
#define MASK2l	(0xffffffffL)
#define MASK2h	(0xffffffff00000000L)
#define CBIT	(0x10000000000000000LL)
#define TBIT	(0x8000000000000000)
#define NOT_MASK2 ((unsigned long long)0xffffffffffffffff0000000000000000LL)
#endif

#ifdef THIRTY_TWO_BIT
#define BN_ULLONG	unsigned long long
#define BN_ULONG	unsigned long
#define BN_LONG		long
#define BITS	64
#define BYTES	4
#define BITS2	32
#define BITS4	16
#define MASK2	(0xffffffffL)
#define MASK2l	(0xffff)
#define MASK2h	(0xffff0000L)
#define CBIT	((unsigned long long)0x100000000LL)
#define TBIT	(0x80000000L)
#define NOT_MASK2 ((unsigned long long)0xffffffff00000000LL)
#endif

#ifdef SIXTEEN_BIT
#define BN_ULLONG	unsigned long
#define BN_ULONG	unsigned short
#define BN_LONG		short
#define BITS	32
#define BYTES	2
#define BITS2	16
#define BITS4	8
#define MASK2	(0xffff)
#define MASK2l	(0xff)
#define MASK2h	(0xff00)
#define CBIT	((unsigned long)0x10000L)
#define TBIT	(0x8000)
#define NOT_MASK2 ((unsigned long)0xffff0000L)
#endif

#define DEFAULT_BITS	32

typedef struct bignum_st
	{
	int top;	/* Index of last used d. */
	BN_ULONG *d;	/* Pointer to an array of 'BITS2' bit chunks. */
	/* The next are internal book keeping for bn_expand. */
	int max;	/* Size of the d array. */
	int neg;
	} BIGNUM;

#define bn_num_bytes(a)	((bn_num_bits(a)+7)/8)
#define bn_is_zero(a)	(((a)->top <= 1) && ((a)->d[0] == 0))
#define bn_is_one(a)	(((a)->top == 1) && ((a)->d[0] == 1))


#define bn_fix_top(a) \
	{ \
	BN_ULONG *l; \
	for (l= &((a)->d[(a)->top-1]); (a)->top > 0; (a)->top--) \
		if (*(l--)) break; \
	}

#ifdef PROTO
int	bn_num_bits(BIGNUM *a);
BIGNUM *bn_new(void);
BIGNUM *bn_copy(BIGNUM *a, BIGNUM *b);
BIGNUM *bn_bin2bn(int len, unsigned char *s, BIGNUM *ret);
int	bn_bn2bin(BIGNUM *a, unsigned char *to);
int	bn_sub(BIGNUM *r, BIGNUM *a, BIGNUM *b);
int	bn_add(BIGNUM *r, BIGNUM *a, BIGNUM *b);
int	bn_mod(BIGNUM *rem, BIGNUM *m, BIGNUM *d);
int	bn_div(BIGNUM *dv, BIGNUM *rem, BIGNUM *m, BIGNUM *d);
int	bn_mul(BIGNUM *r, BIGNUM *a, BIGNUM *b);
BIGNUM *bn_get_reg(void);
int	bn_get_tos(void);
void	bn_set_tos(int a);
BN_ULONG bn_mod_word(BIGNUM *a, unsigned long w);
int	bn_mod2_init(BIGNUM *d, int max_bits);
int	bn_mod2(BIGNUM *ret, BIGNUM *m, BIGNUM *d);
int	bn_add_word(BIGNUM *a, unsigned long w);
int	bn_set_word(BIGNUM *a, unsigned long w);
void	bn_clean_up(void);
int	bn_cmp(BIGNUM *a, BIGNUM *b);
void	bn_free(BIGNUM *a);
int	bn_is_bit_set(BIGNUM *a, int n);
int	bn_lshift(BIGNUM *r, BIGNUM *a, int n);
int	bn_lshift1(BIGNUM *r, BIGNUM *a);
int	bn_mod_exp(BIGNUM *r, BIGNUM *a, BIGNUM *p, BIGNUM *m);
int	bn_modmul_recip(BIGNUM *r, BIGNUM *x, BIGNUM *y, BIGNUM *m, BIGNUM *i, int nb);
int	bn_mul_mod(BIGNUM *ret, BIGNUM *a, BIGNUM *b, BIGNUM *m);
int	bn_one(BIGNUM *a);
void	bn_print(FILE *fp, BIGNUM *a);
int	bn_reciprical(BIGNUM *r, BIGNUM *m);
int	bn_rshift(BIGNUM *r, BIGNUM *a, int n);
int	bn_rshift1(BIGNUM *r, BIGNUM *a);
void	bn_zero(BIGNUM *a);
BIGNUM *bn_expand(BIGNUM *b, int bits);
BIGNUM *bn_dup(BIGNUM *a);
int	bn_Ucmp(BIGNUM *a, BIGNUM *b);
int	bn_clear_bit(BIGNUM *a, int n);
char *	bn_bn2ascii(BIGNUM *a);
int	bn_gcd(BIGNUM *r,BIGNUM *in_a,BIGNUM *in_b);
int bn_inverse_modn(BIGNUM * r, BIGNUM * in_a, BIGNUM * in_n);


#else

int	bn_num_bits();
BIGNUM *bn_new();
BIGNUM *bn_copy();
BIGNUM *bn_bin2bn();
int	bn_bn2bin();
int	bn_sub();
int	bn_add();
int	bn_mod();
int	bn_div();
int	bn_mul();
BIGNUM *bn_get_reg();
int	bn_get_tos();
void	bn_set_tos();
BN_ULONG bn_mod_word();
int	bn_mod2_init();
int	bn_add_word();
int	bn_set_word();
void	bn_clean_up();
int	bn_cmp();
void	bn_free();
int	bn_is_bit_set();
int	bn_lshift();
int	bn_lshift1();
int	bn_mod_exp();
int	bn_modmul_recip();
int	bn_mul_mod();
int	bn_one();
void	bn_print();
int	bn_reciprical();
int	bn_rshift();
int	bn_rshift1();
void	bn_zero();
BIGNUM *bn_expand();
BIGNUM *bn_dup();
int	bn_Ucmp();
int	bn_clear_bit();
char *	bn_bn2ascii();
int	bn_gcd();
int bn_inverse_modn();


#endif

#endif
