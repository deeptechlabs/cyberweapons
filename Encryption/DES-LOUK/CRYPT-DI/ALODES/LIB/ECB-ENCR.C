#include "des-private.h"

/* input data is not modified. output is written after input has been
   read */

/* The least significant bit of input->data[0] is bit # 1 in
   DES-sepcification etc. */

#if (__GNUC__)
#define STATIC_INLINE static inline
#include "des-fun.h"
#endif

int
des_ecb_encrypt2(input,output,schedule,mode,saltvalue)

C_Block		*input;
C_Block		*output;
Key_schedule	*schedule;
int		mode;
des_u_long	saltvalue;

{
  C_Block	ibuf;
  des_u_long	L[2],R[2];
  des_u_long	Lnext[2];
  int	i;
  int	encrypt;

#if BIG_ENDIAN
  des_reverse(input,&ibuf);
  if (mode & DES_REVBITS)
    des_bitrev(&ibuf,&ibuf);
  if (!(mode & DES_NOIPERM)) {
    des_do_iperm(&ibuf,&ibuf);
  }
#else
  if (!(mode & DES_NOIPERM)) {
    if (mode & DES_REVBITS) {
      des_bitrev(input,&ibuf);
      des_do_iperm(&ibuf,&ibuf);
    } else {
      des_do_iperm(input,&ibuf);
    }
  } else {
    if (mode & DES_REVBITS)
      des_bitrev(input,&ibuf);
    else
      copy8(*input,ibuf);
  }
#endif
  encrypt = !(mode & DES_DECRYPT);
  des_expand(&ibuf.data[0],&L[0]);
  des_expand(&ibuf.data[4],&R[0]);
  for(i = 0; i < 16; i++) {
    des_u_long	s = 0;
    copy8(*R,*Lnext);
    s = saltvalue&(R[0]^R[1]);
    R[0] ^= s;
    R[1] ^= s;
    des_fun(R,schedule,encrypt ? i : 15 - i);
    R[0] ^= L[0];
    R[1] ^= L[1];
    copy8(*Lnext,*L);
  }
  
  val4(ibuf.data[0]) = des_unexpand(R);
  val4(ibuf.data[4]) = des_unexpand(L);
#if BIG_ENDIAN
  if (!(mode & DES_NOFPERM))
    des_do_fperm(&ibuf,&ibuf);
  des_reverse(&ibuf,output);
#else
  if (!(mode & DES_NOFPERM))
    des_do_fperm(&ibuf,output);
  else
    copy8(ibuf,*output);
#endif
  if (mode & DES_REVBITS)
    des_bitrev(output,output);
}
