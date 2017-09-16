#define MP_PRIVATE 1
#include "amp.h"

mp_cmp(a,b)

amp	*a,*b;

{
  int	r;
  mp_remove_zeros(a);
  mp_remove_zeros(b);

  if (a->sign == MP_POSITIVE) {
    if (b->sign == MP_NEGATIVE)
      return 1;
    else
      return mp_cmp_internal(a,b);
  } else {
    if (b->sign == MP_POSITIVE)
      return -1;
    else
      return mp_cmp_internal(b,a);
  }
}

mp_cmp_internal(a,b)

amp	*a,*b;

{
  int	a_len;
  int	b_len;
  int	i;

  if (a->denom || b->denom) {
    amp	*d;

    d = mp_sub(a,b);
    if (d->sign == MP_NEGATIVE)
      i = -1;
    else if (MP_EQ_SMALL(d,0))
      i = 0;
    else
      i = 1;
    mp_free(d);
    return i;
  }
  mp_remove_zeros(a);
  mp_remove_zeros(b);
  
  if ((a_len = a->len) > (b_len = b->len))
    return 1;
  if (a_len < b_len)
    return -1;
  for(i = a_len-1; i >= 0; i--) {
    mp_int	ax,bx;
    if ((ax = a->data[i]) > (bx = b->data[i]))
      return 1;
    if (ax < bx)
      return -1;
  }
  return 0;
}
