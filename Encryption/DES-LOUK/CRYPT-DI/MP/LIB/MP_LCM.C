#include "amp.h"
amp *
mp_lcm(result,a,b)

amp	*result;
amp	*a;
amp	*b;

{
  amp	*g0;
  amp	*g1;
  amp	*g2;
  amp	*tmp;

  g0 = mp_mul(a,b);
  g1 = mp_gcd((amp*)0,a,b);
  g2 = mp_itom(0);
  mp_div_to(g0,g0,g1,g2);
  mp_free(g1);
  mp_free(g2);
  if (result) {
    mp_copy_to(result,g0);
    mp_free(g0);
    return result;
  } else {
    return g0;
  }
}
