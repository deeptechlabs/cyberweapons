#include "des-private.h"

des_sun_key(key,p)

char	*key;
C_Block	*p;

{
  int	i,j,c,x;
  for(i = 0; i < 8 && key[i]; i++)
    p->data[i] = key[i];
  for(; i < 8 && key[i]; i++)
    p->data[i] = 0;
  for(i = 0; i < 8; i++) {
    c = p->data[i] & 0x7f;
    x = 1;
    for(j = 0; j < 7; j++) {
      if ((c >> j) & 01)
	x = !x;
    }
    p->data[i] = c | (x << 7);
  }
  des_bitrev(p,p);
}
