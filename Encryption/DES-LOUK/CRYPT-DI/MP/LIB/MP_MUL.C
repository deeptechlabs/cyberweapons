#define MP_PRIVATE 1
#include "amp.h"

amp *
mp_mul(a,b)

amp	*a,*b;

{
  return mp_mul_to((amp*)0,a,b);
}

amp *
mp_mul_to(r,a,b)

amp	*r,*a,*b;

{
  int	i;
  int	l1,l2;
  mp_int	*dp0,*edp0,*dp1;

  l1 = a->len;
  l2 = b->len;
  if (!r)
    r = new_amp_n(l1+l2);
  else {
    MP_TOUCH(r);
    MP_NEED(r,l1+l2);
  }
  r->len = l1+l2;
  for(dp0 = &r->data[0], edp0 = &r->data[l1+l2]; dp0 < edp0;)
    *dp0++ = 0;
  for(i = 0; i < l1; i++) {
    mp_long	m1;
    mp_long	x;
    x = 0;
    m1 = a->data[i];
    for(dp0 = &r->data[i], edp0 = dp0+l2, dp1 = &b->data[0]; dp0 < edp0;) {
      x += *dp0 + m1 * *dp1++;
      *dp0++ = x % MP_MOD;
      x /= MP_MOD;
    }
    *dp0 = x;
  }
  mp_remove_zeros(r);
  r->sign = (a->sign != b->sign);
  if (a->denom || b->denom) {
    r->denom = mp_mul_to(r->denom,
			 (a->denom ? a->denom : mp_one),
			 (b->denom ? b->denom : mp_one));
    mp_reduce(r);
  }
  return r;
}
