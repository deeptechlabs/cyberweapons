#include "des-private.h"

/* This is an alternative for standard unix crypt() function */

static char *enc_arr = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

char *
des_crypt(result,key,salt)

char	*result;
char	*key;
char	*salt;

{
  char	*p;
  int	i;
  C_Block	k1,k2;
  static char	result_a[14];

  DES_HASH_INIT();
  
  for(i = 0; i < 8; i++) {
    k1.data[i] = k2.data[i] = 0;
  }
  k1.data[0] = salt[0];
  k2.data[0] = salt[1];
  des_ecb_encrypt(&k1,&k1,&des_hash_key1,DES_ENCRYPT);
  des_ecb_encrypt(&k2,&k2,&des_hash_key2,DES_ENCRYPT);
  i = 0;
  while (i < 40) {
    for(p = key; *p; p++, i++) {
      k1.data[i%8] ^= *p;
      k2.data[i%8] ^= *p;
      des_ecb_encrypt(&k1,&k1,&des_hash_key1,DES_ENCRYPT);
      des_ecb_encrypt(&k2,&k2,&des_hash_key2,DES_ENCRYPT);
    }
  }
  for(i = 0; i < 8; i++) {
    k1.data[i] ^= k2.data[i];
  }
  if (!result)
    result = result_a;
  p = result;
  *p++ = salt[0];
  *p++ = salt[1];
  for(i = 0; i < 11; i++) {
    int	x, ind, off;
    ind = (i*6)/8;
    off = (i*6)%8;
    x = (k1.data[ind] >> off) & 077;
    if (ind < 7 && off > 2) {
      x |= (k1.data[ind+1] << (8 - off)) & 077;
    }
    *p++ = enc_arr[x];
  }
  *p = 0;
  return result;
}
