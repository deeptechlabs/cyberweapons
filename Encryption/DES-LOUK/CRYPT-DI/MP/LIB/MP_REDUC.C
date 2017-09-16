#include "amp.h"

int	mp_dont_reduce = 0;

amp *
mp_reduce(a)

amp	*a;

{
  amp	*gcd;
  amp	*denom;

  if (mp_dont_reduce)
    return a;
  if (!(denom = a->denom))
    return a;
  a->denom = 0;
  if (MP_EQ_SMALL(denom,1)) {
    mp_free(denom);
    return a;
  }
  gcd = mp_gcd((amp*)0,a,denom);

  if (MP_EQ_SMALL(gcd,1)) {
    a->denom = denom;
    return a;
  }
  mp_div_to(a,a,gcd,(amp*)0);
  mp_div_to(denom,denom,gcd,(amp*)0);
  mp_free(gcd);
  if (MP_EQ_SMALL(denom,1)) {
    mp_free(denom);
    return a;
  }
  a->denom = denom;
  return a;
}
