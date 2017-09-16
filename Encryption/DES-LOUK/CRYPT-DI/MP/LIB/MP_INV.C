#include "amp.h"
amp *
mp_inv(a,n)

amp	*a;
amp	*n;

{
  amp	*g0;
  amp	*g1;
  amp	*g2;
  amp	*u0;
  amp	*u1;
  amp	*u2;
  amp	*v0;
  amp	*v1;
  amp	*v2;
  amp	*tmp;
  amp	*y;

  g0 = mp_copy(n);
  g1 = mp_copy(a);
  u0 = mp_itom(1);
  v0 = mp_itom(0);
  u1 = mp_itom(0);
  v1 = mp_itom(1);
  g2 = mp_itom(0);
  u2 = mp_itom(0);
  v2 = mp_itom(0);
  tmp = mp_itom(0);
  y = mp_itom(0);

  while (g1->len > 1 || g1->data[0]) {
    amp	*x;
    mp_div_to(y,g0,g1,g2);
    mp_sub_to(u2,u0,mp_mul_to(tmp,y,u1));
    mp_sub_to(v2,v0,mp_mul_to(tmp,y,v1));
    x = g0; g0 = g1; g1 = g2; g2 = x;
    x = u0; u0 = u1; u1 = u2; u2 = x;
    x = v0; v0 = v1; v1 = v2; v2 = x;
  }
  if (v0->sign == MP_NEGATIVE) {
    mp_add_to(v0,v0,n);
  }
  mp_free(g0); mp_free(g1); mp_free(g2);
  mp_free(u0); mp_free(u1); mp_free(u2);
  mp_free(v1); mp_free(v2);
  mp_free(tmp);
  mp_free(y);
  return(v0);
}
