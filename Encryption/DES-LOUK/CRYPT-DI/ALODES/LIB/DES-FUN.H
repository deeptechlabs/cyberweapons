#include "des-private.h"

#if BIG_ENDIAN
#define P_IND(x) (((x)&04) | (3-((x)&03)))
#else
#define P_IND(x) (x)
#endif

/* This function performs f()-function in a slightly modified form. It
   starts with data which has gone through E-permutation and produces
   data which is already E-permuted for the next iteration. */

STATIC_INLINE
des_fun(R,schedule,ki)

des_u_long	*R;
Key_schedule	*schedule;
int		ki;

{
  des_u_long	*keyptr = &schedule->data[ki*2];
  des_u_char	*p;
  des_u_long	F[2];
  des_u_long	R0,R1;
  int		i;
  
  copy8(R[0],F[0]);
  F[0] ^= keyptr[0];
  F[1] ^= keyptr[1];
  p = (des_u_char*)F;
  R0 = R1 = 0;
  i = 0;
  R0 ^= des_spe_table[i++*64 + p[P_IND(0)]];
  R1 ^= des_spe_table[i++*64 + p[P_IND(0)]];
  R0 ^= des_spe_table[i++*64 + p[P_IND(1)]];
  R1 ^= des_spe_table[i++*64 + p[P_IND(1)]];
  R0 ^= des_spe_table[i++*64 + p[P_IND(2)]];
  R1 ^= des_spe_table[i++*64 + p[P_IND(2)]];
  R0 ^= des_spe_table[i++*64 + p[P_IND(3)]];
  R1 ^= des_spe_table[i++*64 + p[P_IND(3)]];
  R0 ^= des_spe_table[i++*64 + p[P_IND(4)]];
  R1 ^= des_spe_table[i++*64 + p[P_IND(4)]];
  R0 ^= des_spe_table[i++*64 + p[P_IND(5)]];
  R1 ^= des_spe_table[i++*64 + p[P_IND(5)]];
  R0 ^= des_spe_table[i++*64 + p[P_IND(6)]];
  R1 ^= des_spe_table[i++*64 + p[P_IND(6)]];
  R0 ^= des_spe_table[i++*64 + p[P_IND(7)]];
  R1 ^= des_spe_table[i++*64 + p[P_IND(7)]];
  R[0] = R0;
  R[1] = R1;
}
