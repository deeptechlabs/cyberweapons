#ifndef NEWMP_H
#define NEWMP_H

#if MP_PRIVATE
#if (!__STDC__)
#define const
#endif
#endif

#define MP_BITS	(16)
#define MP_MOD	(1 << MP_BITS)

#define MP_EXTRA	10

/* This should be defined as 1 if trickery like (p == (amp*)1)
works correctly. Otherwise, define it as 0 */
#define MP_ADDR_KLUDGE 1

typedef unsigned short	mp_int;	/* 16-bit unsigned integer */
typedef unsigned long	mp_long;/* 32-bit unsigned integer */

#define MP_SIZE_FOR_LONG	(sizeof(long)/sizeof(mp_int)+2)

typedef struct amp_s {
  int	len;
  int	buflen;
  mp_int	*data;
  int	d_str_len;
  struct amp_s	*denom;		/* Denominator, NULL means 1 */
  char	*d_str;			/* Decimal string */
  char	d_str_valid;		/* Also tell the base */
  char	sign;
  char	not_malloced;
} amp;

#define	MP_POSITIVE	0
#define	MP_NEGATIVE	1

extern char	*mp_alloc();
extern char	*mp_realloc();
amp	*new_amp0();
amp	*mp_itom_to();
amp	*mp_itom();
amp	*mp_atom();
char	*mp_mtoa();
amp	*mp_htom();
amp	*mp_xtom();
char	*mp_mtoh();

amp	*mp_gcd();
amp	*mp_lcm();
amp	*mp_reduce();
amp	*mp_add();
amp	*mp_add_internal();
amp	*mp_add_to();
amp	*mp_sub();
amp	*mp_sub_to();
amp	*mp_mul_x();
amp	*mp_mul_x_to();
amp	*mp_div_x();
amp	*mp_div_x_to();
amp	*mp_div();
amp	*mp_div_to();
amp	*mp_rdiv();
amp	*mp_rdiv_to();
amp	*mp_mul();
amp	*mp_mul_to();
amp	*mp_pow();
amp	*mp_pow_to();
amp	*mp_rpow();
amp	*mp_rpow_to();
amp	*mp_inv();
amp	*mp_sqrt();
amp	*mp_sqrt_to();
amp	*mp_copy();
amp	*mp_copy_to();
amp	*mp_random();
int	mp_bit_length();
amp	*mp_remove_zeros0();
extern amp	*mp_string_to_num();
extern char	*mp_num_to_string();

extern int mp_debug;

extern amp	*mp_zero;
extern amp	*mp_one;

extern amp	mp_dont_allocate; /* This is used as initializer, too */
#if MP_ADDR_KLUDGE
#define MP_DONT_ALLOCATE ((amp*)1)
#else
#define MP_DONT_ALLOCATE (&mp_dont_allocate)
#endif

#define mp_dprint(s,x) (mp_debug ? fprintf(stderr,(s),(x)) : 0)

#define new_amp() new_amp0(10)
#define new_amp_n(n) new_amp0(n)

#define mp_remove_zeros(p) (((p)->data[(p)->len-1]) ? (p) : \
			    mp_remove_zeros0((p)))

#define MP_NEW(type) ((type*)mp_alloc(sizeof(type)))
#define MP_NEW_N(type,n) ((type*)mp_alloc((n)*sizeof(type)))

#define MP_NEED(p,n) (((n) <= (p)->buflen) ? 0 : mp_need((p),(n)))
#define MP_TOUCH(p) ((p)->d_str_valid = 0)

#define MP_EQ_SMALL(p,x) ((p)->len == 1 && (p)->data[0] == (x))
#define MP_ASSIGN_SMALL(p,x) ((p)->len = 1, (p)->data[0] = (x))

#define MP_SWAP(a,b,tmp) ((tmp)=(a),(a)=(b),(b)=(tmp))

#endif
