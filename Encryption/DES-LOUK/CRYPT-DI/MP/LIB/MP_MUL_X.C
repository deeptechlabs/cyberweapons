#define MP_PRIVATE 1
#include "amp.h"

amp *
mp_mul_x(a,x)

amp	*a;
mp_long	x;

{
  return mp_mul_x_to((amp*)0,a,x);
}

amp *
mp_mul_x_to(r,a,z)

amp	*r,*a;
mp_long	z;

{
  int	l;
  mp_long	x;
  mp_int	*dp0;
  mp_int	*dp1;
  mp_int	*edp0;

  if (z > MP_MOD)
    return 0;
  l = a->len;
  if (!r)
    r = new_amp_n(l+1);
  else {
    MP_TOUCH(r);
    MP_NEED(r,l+1);
  }
  if (z == 0) {
    r->data[0] = 0;
    r->len = 1;
    return r;
  }
  x = 0;
  for(dp0 = &r->data[0], edp0 = dp0+l, dp1 = &a->data[0]; dp0 < edp0;) {
    x += z * *dp1++;
    *dp0++ = x % MP_MOD;
    x /= MP_MOD;
  }
  if (x) {
    *dp0++ = x;
  }
  r->len = dp0 - &r->data[0];
  return r;
}
