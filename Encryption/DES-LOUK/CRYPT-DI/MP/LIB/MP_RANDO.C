/* -*-c-*- */
#include "des.h"
#define MP_PRIVATE 1
#include "amp.h"

C_Block		mp_random_data;

mp_set_seed_string(p)

char	*p;

{
  string_to_key(p,&mp_random_data);
}

mp_set_seed(p)

unsigned char	*p;

{
  int	i;
  for(i = 0; i < 8; i++)
    mp_random_data.data[i] = p[i];
}

mp_random_next(b)

unsigned char	*b;

{
  DES_HASH_INIT();
  des_ecb_encrypt(&mp_random_data,&mp_random_data,&des_hash_key1,DES_ENCRYPT);
  bcopy(&mp_random_data,b,sizeof(mp_random_data));
}

amp *
mp_random(r,n)

amp	*r;
amp	*n;

{
  int	i;
  int	j;
  mp_long	x;
  mp_long	mask;
  unsigned char	b[8];
  unsigned char	*p;
  int	len;

  mp_remove_zeros(n);
  len = n->len;
  if (!r) {
    r = new_amp_n(len);
  } else {
    MP_TOUCH(r);
    MP_NEED(r,len);
  }

  mask = n->data[len-1];
  for(i = 0; i < MP_BITS; i++)
    mask |= mask/2;

  r->len = len;
  for(;;) {
    for(i = 0; i < len; i++) {
      mp_random_next(b);
      x = 0;
      for(p = b, j = 0; j < MP_BITS; j += 8) {
	x = (x << 8) | ((*p++)&0xff);
      }
      r->data[i] = x;
    }
    r->data[len-1] &= mask;
    for(i = len-1; i >= 0; i--) {
      if (r->data[i] < n->data[i])
	goto found;
      if (r->data[i] > n->data[i])
	break;
    }
  }
 found:
  mp_remove_zeros(r);
  return r;
}
