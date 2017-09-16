#define MP_PRIVATE 1
#include "amp.h"

amp *
mp_remove_zeros0(p)

amp	*p;

{
  int	l;

  for(l = p->len-1; l > 0 && p->data[l] == 0; l--)
    ;
  if (l == 0 && p->data[0] == 0)
    p->sign = MP_POSITIVE;
  p->len = l+1;
  return p;
}
