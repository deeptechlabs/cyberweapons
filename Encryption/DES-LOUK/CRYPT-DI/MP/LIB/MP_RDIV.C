#include <stdio.h>
#define MP_PRIVATE 1
#include "amp.h"

amp *
mp_rdiv(a,b)

amp	*a,*b;

{
  return mp_rdiv_to((amp*)0,a,b);
}

amp *
mp_rdiv_to(r,a,b)

amp	*r;
amp	*a;
amp	*b;

{
  amp	*b_denom;
  r = mp_copy_to(r,a);
  if (b_denom = b->denom) {
    mp_mul_to(r,b_denom);
  }
  b->denom = 0;
  r->denom = mp_mul_to(r->denom,
		       (a->denom ? a->denom : mp_one),
		       b);
  b->denom = b_denom;
  return mp_reduce(r);
}
