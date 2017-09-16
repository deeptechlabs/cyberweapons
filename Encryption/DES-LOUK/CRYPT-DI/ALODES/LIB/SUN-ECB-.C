#include "des.h"

ecb_crypt(key,buf,len,sun_mode)

char	*key;
char	*buf;
int	len;
int	sun_mode;

{
  int	mode;
  C_Block	key_int;
  Key_schedule	schedule;

  mode = DES_REVBITS;
  mode |= (sun_mode & 1) ? DES_DECRYPT : DES_ENCRYPT;
  des_bitrev(key,&key_int);
  des_set_key(&key_int,&schedule);
  for(; len >= 8; len -= 8, buf += 8) {
    des_ecb_encrypt(buf,buf,&schedule,mode);
  }
  return 0;
}
