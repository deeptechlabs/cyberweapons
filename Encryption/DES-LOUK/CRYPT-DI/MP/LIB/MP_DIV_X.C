#define MP_PRIVATE 1
#include "amp.h"

amp *
mp_div_x(a,x,rp)

amp	*a;
mp_long	x;
mp_long	*rp;

{
  return mp_div_x_to((amp*)0,a,x,rp);
}

amp *
mp_div_x_to(r,a,z,rp)

amp	*r,*a;
mp_long	z;
mp_long	*rp;

{
  int	i;
  int	l;
  mp_long	x;

  if (!r) {
    r = new_amp_n(a->len);
  }
  if (r == MP_DONT_ALLOCATE)
    r = 0;
  l = a->len;
  if (r) {
    MP_TOUCH(r);
    MP_NEED(r,l);
  }
  x = 0;
  for(i = l-1; i >= 0; i--) {
    x = x * MP_MOD + a->data[i];
    if (r)
      r->data[i] = x / z;
    x = x % z;
  }
  if (rp) *rp = x;
  if (r) {
    r->len = l;
    mp_remove_zeros(r);
  }
  return r;
}
