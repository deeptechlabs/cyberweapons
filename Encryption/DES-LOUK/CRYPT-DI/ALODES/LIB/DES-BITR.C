#include "des-private.h"

static des_u_char rev8bits[] = {
#include "eight.h"
};

des_bitrev(ib,ob)

C_Block	*ib;
C_Block	*ob;

{
  des_u_char	*ip,*eip,*op;

  for(ip = &ib->data[0], eip = ip+8, op = &ob->data[0]; ip < eip;) {
    *op++ = rev8bits[*ip++];
  }
}
