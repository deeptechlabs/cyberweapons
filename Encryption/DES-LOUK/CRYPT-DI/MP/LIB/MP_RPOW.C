#define MP_PRIVATE 1
#include "amp.h"

amp *
mp_rpow(a,z)

amp	*a;
amp	*z;

{
  return mp_rpow_to((amp*)0,a,z);
}

amp *
mp_rpow_to(r,a,z)

amp	*r;
amp	*a;
amp	*z;

{
  int	i;
  int	j;
  amp	*tmp;
  amp	*tmp2;
  int	z_len;

  if (!r)
    r = mp_itom((mp_long)1);
  else {
    MP_TOUCH(r);
    r->data[0] = 1;
    r->len = 1;
  }

  mp_remove_zeros(z);

  a = mp_copy(a);
  tmp = new_amp();

  z_len = z->len;
  for(i = 0; i < z_len; i++) {
    int		last_round;
    mp_int	x;
    last_round = (i+1 == z_len);
    x = z->data[i];
    for(j = 0; j < MP_BITS; j++) {
      if (x & 01) {
	mp_mul_to(tmp,r,a);
	mp_copy_to(r,tmp);
      }
      x >>= 1;
      if (last_round && x == 0)
	break;
      mp_mul_to(tmp,a,a);
      MP_SWAP(tmp,a,tmp2);
    }
  }
  mp_free(tmp);
  return r;
}
