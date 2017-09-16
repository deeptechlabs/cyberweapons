#define MP_PRIVATE 1
#include "amp.h"

int
mp_bit_length(a)

amp	*a;

{
  int	l;
  mp_int	x;
  mp_remove_zeros(a);
  l = a->len-1;
  x = a->data[l];
  l *= MP_BITS;
  while (x > 1) {
    l++;
    x /= 2;
  }
  return l;
}
