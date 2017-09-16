#include "des.h"

des_key_to_hex(k,h)

C_Block	*k;
char	*h;

{
  int	i,j,x;
  
  for(i = 0; i < 8; i++) {
    x = k->data[i];
    for(j = 0; j < 2; j++,x <<= 4) {
      *h++ = "0123456789abcdef"[(x&0xf0)>>4];
    }
  }
  *h = 0;
}

des_hex_to_key(h,k)

char	*h;
C_Block	*k;

{
  int	i,j,a,c;

  for(i = 0; i < 8; i++) {
    a = 0;
    for(j = 0; j < 2; j++) {
      c = *h++;
      if (c >= '0' && c <= '9') {
	c -= '0';
      } else if (c >= 'a' && c <= 'f') {
	c -= ('a' - 10);
      } else if (c >= 'A' && c <= 'F') {
	c -= ('A' - 10);
      } else {
	return -1;
      }
      a = a * 16 + c;
    }
    k->data[i] = a;
  }
  return 0;
}
