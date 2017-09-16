#include "des-private.h"

/* des_cbc_cksum computes a cryptographical checksum of input data */

des_u_long
des_cbc_cksum(input,output,length,schedule,ivec,mode)

C_Block		*input;
C_Block		*output;
int		length;
Key_schedule	*schedule;
C_Block		*ivec;
int		mode;

{
  C_Block	vbuf;
  int		l;

  if (!ivec) {
    vbuf = *ivec;
  } else {
    vbuf = des_zero_block;
    val4(vbuf.data[0]) = val4(vbuf.data[4]) = 0;
  }
  for (; length > 0; length -= 8, input++) {
    l = (length > 8) ? 8 : length;
    des_cbc_encrypt(input,output,l,schedule,&vbuf,DES_ENCRYPT|mode);
  }
  return val4(output->data[4]);
}
