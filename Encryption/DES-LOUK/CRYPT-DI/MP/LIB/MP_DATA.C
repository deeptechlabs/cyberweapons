#define MP_PRIVATE 1
#include "amp.h"
amp	mp_dont_allocate;
static const mp_int	zero_arr[] = { 0 };
static const mp_int	one_arr[] = { 1 };
static amp	mp_zero_z = {
  1,				/* len */
  1,				/* buflen */
  zero_arr,			/* data */
  0,				/* d_str_len */
  0,				/* denom */
  0,				/* d_str */
  0,				/* d_str_valid */
  MP_POSITIVE,			/* sign */
  1				/* not_malloced */
};
static amp	mp_one_z = {
  1,				/* len */
  1,				/* buflen */
  one_arr,			/* data */
  0,				/* d_str_len */
  0,				/* denom */
  0,				/* d_str */
  0,				/* d_str_valid */
  MP_POSITIVE,			/* sign */
  1				/* not_malloced */
};
amp	*mp_zero = &mp_zero_z;
amp	*mp_one = &mp_one_z;
