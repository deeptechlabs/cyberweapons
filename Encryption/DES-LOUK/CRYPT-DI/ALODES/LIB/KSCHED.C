#include "des-private.h"

const static char	PC1[] = {
    56,48,40,32,24,16, 8,
     0,57,49,41,33,25,17,
     9, 1,58,50,42,34,26,
    18,10, 2,59,51,43,35,
    62,54,46,38,30,22,14,
     6,61,53,45,37,29,21,
    13, 5,60,52,44,36,28,
    20,12, 4,27,19,11, 3,
};

const static char	PC2[] = {
    13,16,10,23, 0, 4,
     2,27,14, 5,20, 9,
    22,18,11, 3,25, 7,
    15, 6,26,19,12, 1,
    40,51,30,36,46,54,
    29,39,50,44,32,47,
    43,48,38,55,33,52,
    45,41,49,35,28,31,
  };

const static char	LS[] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};

const static des_u_long	shift_arr[] = {
    0x1, 0x2, 0x4, 0x8,
    0x10, 0x20, 0x40, 0x80,
    0x100, 0x200, 0x400, 0x800,
    0x1000, 0x2000, 0x4000, 0x8000,
    0x10000, 0x20000, 0x40000, 0x80000,
    0x100000, 0x200000, 0x400000, 0x800000,
    0x1000000, 0x2000000, 0x4000000, 0x8000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000,
};

/* Key schedule calculation could be done with precomputed inline code
   similarly to 64-bit permutation calculation, but it would take about
   18kbytes of code space */

/* The least significant bit of key->data[0] is bit # 1 in
   DES-sepcification etc. */

des_set_key_slow(key,schedule)

C_Block	*key;
Key_schedule	*schedule;

{
    des_u_long	*kp;
    des_u_long	Result_0;
    des_u_long	Result_1;
    des_u_long	*Input;
    int		i;
    int		j;
    int		sa = 0;
    int		Tmp;
    int		result_bit;
    int		side;
    int		column;
    int		result_side;
#if BIG_ENDIAN
    C_Block	t;
#endif

#if BIG_ENDIAN
    des_reverse(key,&t);
    Input = (des_u_long*)(t.data);
#else
    Input = (des_u_long*)key->data;
#endif
    kp = schedule->data;
    for(i = 0; i < 16; i++) {
	sa += LS[i];
	Result_0 = Result_1 = 0;
	result_side = 0;
	for(j = 0; j < 48; j++) {
	    Tmp = PC2[j];
	    side = (Tmp >= 28);
	    column = (Tmp + sa) % 28;
	    column = PC1[column + side*28];
	    if (column >= 32) {
		side = 1;
		column -= 32;
	    } else {
		side = 0;
	    }
	    if (j >= 24) {
		result_side = 1;
		result_bit = j-24;
	    } else {
		result_bit = j;
	    }
	    result_bit = (result_bit/6)*8 + (result_bit%6);
	    if (Input[side] & shift_arr[column]) {
		if (result_side) {
		    Result_1 |= shift_arr[result_bit];
		} else {
		    Result_0 |= shift_arr[result_bit];
		}
	    }
	}
	*kp++ = Result_0; *kp++ = Result_1;
    }
}

des_set_key_slow_rev(key,schedule)

C_Block	*key;
Key_schedule	*schedule;

{
  C_Block	x;

  des_bitrev(key,&x);
  des_set_key_slow(&x,schedule);
}
