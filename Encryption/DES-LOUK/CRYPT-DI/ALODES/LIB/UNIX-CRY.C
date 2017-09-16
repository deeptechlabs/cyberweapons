#include "des-private.h"
#include <stdio.h>

static int
from64(c)

int	c;

{
  int	o = 0;
#define foo1(a,b) if (c >= a && c <= b) return c-a+o;  o += b-a+1;
  foo1('.','/');
  foo1('0','9');
  foo1('A','Z');
  foo1('a','z');
  return -1;
}

char *
unix_crypt(pw,salt)

char	*pw;
char	*salt;

{
  C_Block	ukey;
  int		c;
  int		i,j,k;
  int		saltbits;
  des_u_long	saltvalue;
  Key_schedule	sched;
  static char	r[14];
  C_Block	x;

  ukey = des_zero_block;

  for(i = 0; i < 8 && (c = pw[i]&0xff); i++) {
    for(j = 0; j < 7; j++) {
      if (c & (1 << j)) ukey.data[i] |= (1 << (6-j));
    }
  }
  saltvalue = from64(salt[0]) | (from64(salt[1]) << 8);
  des_set_key(&ukey,&sched);
  x = des_zero_block;
  des_ecb_encrypt2(&x,&x,&sched,DES_ENCRYPT|DES_NOFPERM,saltvalue);
  for(i = 0; i < 23; i++)
    des_ecb_encrypt2(&x,&x,&sched,DES_ENCRYPT|DES_NOIPERM|DES_NOFPERM,saltvalue);
  des_ecb_encrypt2(&x,&x,&sched,DES_ENCRYPT|DES_NOIPERM,saltvalue);
  r[0] = salt[0];
  r[1] = salt[1];
  k = 0;
  for(i = 0; i < 11; i++) {
    int	c;
    c = 0;
    for(j = 0; j < 6; j++) {
      c <<= 1;
      c |= (k < 64) ? ((x.data[k/8] >> (k % 8)) & 01) : 0;
      k++;
    }
    r[i+2] =
      "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"[c];
  }
  r[13] = 0;
  return r;
}
