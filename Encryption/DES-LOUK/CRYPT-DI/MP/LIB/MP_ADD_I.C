#define MP_PRIVATE 1
#include "amp.h"

amp *
mp_add_internal(r,a_in,b_in,subflag)

amp	*r,*a_in,*b_in;
int	subflag;

{
  int	i;
  int	l1,l2,l;
  mp_long	x;
  char	a_sign,b_sign;
  char	r_sign = MP_POSITIVE;
  amp	*d_a = 0;
  amp	*d_b = 0;
  amp	*a,*b;

  if (a_in->denom || b_in->denom) {
    d_a = a_in->denom; a_in->denom = 0;
    d_b = b_in->denom; b_in->denom = 0;
    if (d_a)
      b = mp_mul_to((amp*)0,b_in,d_a);
    else
      b = mp_copy(b_in);
    if (d_b)
      a = mp_mul_to((amp*)0,a_in,d_b);
    else
      a = mp_copy(a_in);
  } else {
    a = a_in;
    b = b_in;
  }

  a_sign = a->sign;
  b_sign = b->sign;
  if (subflag) b_sign = !b_sign;
  if (a_sign == MP_NEGATIVE) {
    a_sign = !a_sign;
    b_sign = !b_sign;
    r_sign = !r_sign;
  }
  l1 = a->len;
  l2 = b->len;
  l = l1;
  if (l2 > l1) l = l2;
  if (!r) {
    r = new_amp_n(l);
  } else {
    MP_TOUCH(r);
    MP_NEED(r,l);
  }
  if (b_sign == MP_POSITIVE) {
    x = 0;
    for(i = 0; i < l1 || i < l2; i++) {
      if (i < l1) x += a->data[i];
      if (i < l2) x += b->data[i];
      r->data[i] = x % MP_MOD;
      x /= MP_MOD;
    }
    if (x) {
      r->data[i] = x;
      i++;
    }
    r->len = i;
    r->sign = r_sign;
  } else {
    if (mp_cmp_internal(a,b) < 0) {
      amp	*z;
      z = a; a = b; b = z;
      r_sign = !r_sign;
      l1 = a->len;
      l2 = b->len;
    }
    x = MP_MOD;
    for(i = 0; i < l1 || i < l2; i++) {
      if (i < l1) x += a->data[i];
      if (i < l2) x -= b->data[i];
      r->data[i] = x % MP_MOD;
      x /= MP_MOD;
      x += MP_MOD-1;
    }
    r->len = i;
    r->sign = r_sign;
    mp_remove_zeros(r);
  }
  if (d_a || d_b) {
    amp	*tmp;
    a_in->denom = d_a;
    b_in->denom = d_b;
    mp_free(a);
    mp_free(b);
    if (d_a) {
      r->denom = mp_copy_to(r->denom,d_a);
      if (d_b) {
	tmp = mp_copy(r->denom);
	mp_mul_to(r->denom,tmp,d_b);
	mp_free(tmp);
      }
    } else {
      r->denom = mp_copy_to(r->denom,d_b);
    }
    mp_reduce(r);
  }
  return r;
}
