#define MP_PRIVATE 1
#include "amp.h"

amp *
mp_itom(n)

long	n;

{
  return mp_itom_to((amp*)0,n);
}

amp *
mp_itom_to(r,n)

amp	*r;
long	n;

{
  int	i;
  char	r_sign;
  unsigned long	x;

  if (n < 0) {
    r_sign = MP_NEGATIVE;
    x = -n;
  } else {
    r_sign = MP_POSITIVE;
    x = n;
  }
  if (!r) {
    r = new_amp_n(MP_SIZE_FOR_LONG);
  } else {
    MP_TOUCH(r);
    MP_NEED(r,MP_SIZE_FOR_LONG);
  }
  for(i = 0; !i || x; i++) {
    r->data[i] = x % MP_MOD;
    x /= MP_MOD;
  }
  r->len = i;
  r->sign = r_sign;
  return r;
}
