#define MP_PRIVATE 1
#include "amp.h"

amp *
mp_sqrt(a,rp)

amp	*a,*rp;

{
  return mp_sqrt_to((amp*)0,a,rp);
}

/* Got algorithm from news article <77@telxon.UUCP> in comp.lang.c by
   scottf@telxon.UUCP (Scott Fluhrer). However coding with mp library
   calls is by me. Thank you very much Scott!! */

amp *
mp_sqrt_to(r,a,rp)

amp	*r,*a,*rp;

{
  amp	*c;
  amp	*b;
  int	l;
  int	i;
  int	j;

  mp_reduce(a);
  if (a->denom)
    return 0;
  l = a->len;
  l /= 2;
  if (r)
    c = r;
  else
    c = new_amp();
  MP_NEED(c,l+1);
  if (l) {
    for(i = l-1, j = a->len-1; i >= 0; i--,j--)
      c->data[i] = a->data[j];
    c->len = l;
  } else {
    if (a->len == 1 && a->data[0] <= 1) {
      mp_copy_to(c,a);
      return c;
    }
    MP_ASSIGN_SMALL(c,1);
  }
  MP_TOUCH(c);
  b = new_amp();
  mp_div_to(b,a,c,(amp*)0);
  mp_add_to(b,b,c);
  mp_div_x_to(b,b,2,(amp*)0);
  do {
    mp_copy_to(c,b);
    mp_div_to(b,a,c,(amp*)0);
    mp_add_to(b,b,c);
    mp_div_x_to(b,b,2,(amp*)0);
  } while (mp_cmp(c,b) > 0);
  if (rp) {
    mp_mul_to(b,c,c);
    mp_sub_to(rp,a,b);
  }
  mp_free(b);
  return c;
}
