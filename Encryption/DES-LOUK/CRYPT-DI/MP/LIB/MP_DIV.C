#include <stdio.h>
#define MP_PRIVATE 1
#include "amp.h"

amp *
mp_div(a,b,rp)

amp	*a;
amp	*b;
amp	*rp;

{
  return mp_div_to((amp*)0,a,b,rp);
}

/* The alogorith is taken from Knuth's Seminumerical Alogorithms
   p. 257 .. 258. If you don't cpmpletely understand what is going on
   please don't change a bit. */

amp *
mp_div_to(r,a,b,rp)

amp	*r;
amp	*a;
amp	*b;
amp	*rp;

{
  int	l;
  int	j;
  int	k;
  int	a_len;
  int	b_len;
  mp_long	x;
  mp_long	v1;
  mp_long	v2;
  mp_long	qq;
  mp_long	d;
  int	r_sign;

  l = a->len - b->len + 3;
  if (l < MP_EXTRA) l = MP_EXTRA;
  if (!r) {
    r = new_amp_n(l);
  }
  r_sign = (a->sign != b->sign);
  if (b->len < 2) {		/* Let's use div_x routine */
    mp_long	rem;
    mp_div_x_to(r,a,(mp_long)b->data[0],&rem);
    if (rp) {
      MP_TOUCH(rp);
      MP_NEED(rp,1);
      rp->data[0] = rem;
      rp->len = 1;
      rp->sign = r_sign;
    }
    r->sign = r_sign;
    return r;
  }
  MP_TOUCH(r);
  if (a->len < b->len) {	/* result is 0 and remainder is a */
    if (rp && a != rp) {
      mp_copy_to(rp,a);
      rp->sign = r_sign;
    }
    r->data[0] = 0;
    r->len = 1;
    r->sign = r_sign;
    return r;
  }
  if (rp) {
    if (a != rp) {
      mp_copy_to(rp,a);
      a = rp;
    }
  } else {
    a = mp_copy(a);
  }
  MP_NEED(r,l);
  a_len = a->len;
  b_len = b->len;

  d = MP_MOD / (b->data[b_len-1] + 1);
  if (d != 1) {
    mp_mul_x_to(a,a,d);
    b = mp_copy(b);		/* We don't want to modify the real b */
    mp_mul_x_to(b,b,d);
  }
  if (a->len == a_len) {
    MP_NEED(a,a_len+1);
    a->data[a_len] = 0;
    a->len++;
  }
  a_len = a->len;
  MP_NEED(b,b_len+1);
  b->data[b_len] = 0;
  v1 = b->data[b_len-1];
  v2 = b->data[b_len-2];

  for(j = a_len-1; j >= b_len; j--) {
    mp_long	uj;
    mp_long	uj1;
    mp_long	uj2;
    mp_int	*dp;
    mp_int	*dp2;
    mp_int	*edp;

    uj = a->data[j];
    uj1 = a->data[j-1];
    uj2 = a->data[j-2];
    if (uj == v1) {
      qq = MP_MOD-1;
    } else {
      qq = (uj*MP_MOD + uj1)/v1;
    }
    while (((x = uj*MP_MOD + uj1 - qq*v1) < MP_MOD) &&
	   (v2*qq > x*MP_MOD + uj2)) {
      qq--;
    }
    x = ((MP_MOD-1) * MP_MOD);
    for(dp = &a->data[j-b_len], edp = dp+b_len, dp2 = &b->data[0];
	dp <= edp;) {
      x += *dp;
      x -= qq * *dp2++;
      *dp++ = x % MP_MOD;
      x /= MP_MOD;
      x += (MP_MOD-1) * (MP_MOD-1);
    }
    if (x != MP_MOD*(MP_MOD-1)) {
      x = 0;
      for(k = 0; k <= b_len; k++) {
	x += a->data[j-b_len+k];
	x += b->data[k];
	a->data[j-b_len+k] = x % MP_MOD;
	x /= MP_MOD;
      }
      qq--;
    }
    a->data[j] = 0;
    r->data[j-b_len] = qq;
  }
  mp_remove_zeros(a);
  if (rp && d != 1) {
    mp_div_x_to(rp,a,d,(mp_long*)0);
    rp->sign = r_sign;
  }
  r->len = a_len-b_len;
  mp_remove_zeros(r);
  if (!rp)
    mp_free(a);
  if (d != 1)
    mp_free(b);
  r->sign = r_sign;
  return r;
}
