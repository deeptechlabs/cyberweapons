#include "amp.h"

amp *
mp_string_to_num(s)

char	*s;

{
  amp	*a;
  int	c;

  a = mp_itom(0);
  while(c = ((*s++)&0xff)) {
    mp_mul_x_to(a,a,(mp_long)0x100);
    mp_add_x_to(a,(long)(c&0xff));
  }
  return a;
}

char *
mp_num_to_string(a)

amp	*a;

{
  int	l;
  char	*r;
  char	*p;
  char	*q;
  int	tmp;
  mp_long	rem;

  a = mp_copy(a);

  l = (mp_bit_length(a)*8)+4;
  r = mp_alloc(l);
  p = r;

  for(;;) {
    mp_div_x_to(a,a,(mp_long)0x100,&rem);
    if (rem == 0)
      break;
    *p++ = rem;
  }
  *p = 0;
  p--;
  q = r;
  while (q < p) {
    tmp = *q;
    *q = *p;
    *p = tmp;
    q++; p--;
  }
  mp_free(a);
  return r;
}
