#include "des-private.h"

/* This is supposed to be a one-way string-to-key function. If someone
   finds this to be easily reversible, please tell me, too */

string_to_key(asckey,key)

char	*asckey;
C_Block	*key;

{
  char	*p;
  int	i;
  C_Block	k1,k2;

  DES_HASH_INIT();
  
  for(i = 0; i < 8; i++) {
    k1.data[i] = k2.data[i] = 0;
  }
  for(i = 0, p = asckey; *p; p++, i++) {
    i %= 8;
#if 0
    k1.data[i] |= *p;		/* This is wrong, of course */
    k2.data[i] |= *p;
#else
    k1.data[i] ^= *p;
    k2.data[i] ^= *p;
#endif
    des_ecb_encrypt(&k1,&k1,&des_hash_key1,DES_ENCRYPT);
    des_ecb_encrypt(&k2,&k2,&des_hash_key2,DES_ENCRYPT);
  }
  for(i = 0; i < 8; i++) {
    key->data[i] = k1.data[i] ^ k2.data[i];
  }
  return 0;
}
