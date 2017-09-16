#include	"des-private.h"

/* des_do_iperm and des_do_fperm use precomputed inline code to make
   64-bit permutation. This is the fastest method that I know of to make
   this on microVAX II */

des_do_iperm(ibuf,obuf)

des_u_long	*ibuf,*obuf;

{
  des_u_long	L,R,L_result,R_result;
  L_result = R_result = 0;
  L = ibuf[0]; R = ibuf[1];
#include "ip.h"
  obuf[0] = L_result; obuf[1] = R_result;
}

des_do_fperm(ibuf,obuf)

des_u_long	*ibuf,*obuf;

{
  des_u_long	L,R,L_result,R_result;
  L_result = R_result = 0;
  L = ibuf[0]; R = ibuf[1];
#include "fp.h"
  obuf[0] = L_result; obuf[1] = R_result;
}

des_do_iperm_rev(ibuf,obuf)

des_u_long	*ibuf,*obuf;

{
  des_u_long	L,R,L_result,R_result;
  L_result = R_result = 0;
  L = ibuf[0]; R = ibuf[1];
#include "ip-rev.h"
  obuf[0] = L_result; obuf[1] = R_result;
}

des_do_fperm_rev(ibuf,obuf)

des_u_long	*ibuf,*obuf;

{
  des_u_long	L,R,L_result,R_result;
  L_result = R_result = 0;
  L = ibuf[0]; R = ibuf[1];
#include "fp-rev.h"
  obuf[0] = L_result; obuf[1] = R_result;
}
