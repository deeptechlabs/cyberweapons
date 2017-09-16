#include "amp.h"
amp *
mp_gcd(result,a,b)

amp	*result;
amp	*a;
amp	*b;

{
  amp	*g0;
  amp	*g1;
  amp	*g2;
  amp	*tmp;

  g0 = mp_copy(a);
  g1 = mp_copy(b);
  g2 = mp_itom(0);

  while (g1->len > 1 || g1->data[0]) {
    mp_div_to(g0,g0,g1,g2);
    tmp = g0; g0 = g1; g1 = g2; g2 = tmp;
  }
  mp_free(g1);
  mp_free(g2);
#if 0
  mp_free(tmp);
#endif
  if (result) {
    mp_copy_to(result,g0);
    mp_free(g0);
    return result;
  } else {
    return g0;
  }
}
