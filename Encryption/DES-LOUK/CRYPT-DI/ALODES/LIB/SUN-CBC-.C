#include "des.h"

cbc_crypt(key,buf,len,sun_mode,ivec)

char	*key;
char	*buf;
int	len;
int	sun_mode;
char	*ivec;

{
  int	mode;
  C_Block	key_int;
  Key_schedule	schedule;

  mode = DES_REVBITS;
  mode |= (sun_mode & 1) ? DES_DECRYPT : DES_ENCRYPT;
  des_bitrev(key,&key_int);
  des_set_key(&key_int,&schedule);
  des_cbc_encrypt(buf,buf,len,&schedule,ivec,mode);
  return 0;
}
