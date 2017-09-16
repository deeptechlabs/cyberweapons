#include "des-private.h"

/* des_reverse reverses bytes of 64-bit block within 32-bit words. */

des_reverse(ib,ob)

des_u_char	*ib;
des_u_char	*ob;

{
  ob[3] = *ib++;
  ob[2] = *ib++;
  ob[1] = *ib++;
  ob[0] = *ib++;
  ob[7] = *ib++;
  ob[6] = *ib++;
  ob[5] = *ib++;
  ob[4] = *ib++;
}
