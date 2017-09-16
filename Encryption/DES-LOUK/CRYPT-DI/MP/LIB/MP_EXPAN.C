#define MP_PRIVATE 1
#include "amp.h"

amp *
mp_expand(a,b)

amp	*a,*b;

{
  amp	*denom;
  amp	*tmp;

  if (denom = a->denom)
    a->denom = 0;
  tmp = mp_copy(a);
  mp_mul_to(a,tmp,b);
  if (denom) {
    mp_copy_to(tmp,denom);
    mp_mul_to(denom,tmp,b);
    a->denom = denom;
  }
  return a;
}
