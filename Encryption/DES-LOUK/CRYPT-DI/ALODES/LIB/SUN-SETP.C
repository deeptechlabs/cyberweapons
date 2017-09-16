#include "des.h"

/* Believe or not, this is how SUNs secure RPC does encrypting. This
braindamaged code (actually parity table) collapses 56 effective key
bits to 48. */

des_u_char des_sun_parity[] = {
#include "sun-parity.h"
};

des_setparity(key)

des_u_char	*key;

{
  des_u_char	*ep = key+8;

  for(; key < ep; key++) {
    *key = des_sun_parity[(*key)&0x7f];
  }
}
