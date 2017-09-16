#include "des-private.h"

const static des_u_long ksched_arr[] = {
#include "ksched.h"
};

/* The least significant bit of key->data[0] is bit # 1 in
   DES-sepcification etc. */

des_set_key(key,schedule)

C_Block	*key;
Key_schedule	*schedule;

{
  const des_u_long	*kp;
  des_u_long	*kp2;
  int		i;
  int		j;
  
  for(i = 0; i < 32; i++) {
    schedule->data[i] = 0;
  }
  kp = ksched_arr;
  for(i = 0; i < 8; i++) {
    for(j = 0; j < 7; j++) {
      if (key->data[i] & (1 << j)) {
	kp2 = schedule->data;
	*kp2++ |= *kp++; *kp2++ |= *kp++; *kp2++ |= *kp++; *kp2++ |= *kp++;
	*kp2++ |= *kp++; *kp2++ |= *kp++; *kp2++ |= *kp++; *kp2++ |= *kp++;
	*kp2++ |= *kp++; *kp2++ |= *kp++; *kp2++ |= *kp++; *kp2++ |= *kp++;
	*kp2++ |= *kp++; *kp2++ |= *kp++; *kp2++ |= *kp++; *kp2++ |= *kp++;
	*kp2++ |= *kp++; *kp2++ |= *kp++; *kp2++ |= *kp++; *kp2++ |= *kp++;
	*kp2++ |= *kp++; *kp2++ |= *kp++; *kp2++ |= *kp++; *kp2++ |= *kp++;
	*kp2++ |= *kp++; *kp2++ |= *kp++; *kp2++ |= *kp++; *kp2++ |= *kp++;
	*kp2++ |= *kp++; *kp2++ |= *kp++; *kp2++ |= *kp++; *kp2++ |= *kp++;
      } else {
	kp += 32;
      }
    }
  }
}

des_set_key_rev(key,schedule)

C_Block	*key;
Key_schedule	*schedule;

{
  C_Block	x;

  des_bitrev(key,&x);
  des_set_key(&x,schedule);
}
