#include "des-private.h"

/* des_hash_init prepares two key schedules to be used with
   hash-function calculation by des algorithm */

static unsigned char hash_key1[8] =
  { 0x9a, 0xd3, 0xbc, 0x24, 0x10, 0xe2, 0x8f, 0x0e };
static unsigned char hash_key2[8] =
  { 0xe2, 0x95, 0x14, 0x33, 0x59, 0xc3, 0xec, 0xa8 };

Key_schedule	des_hash_key1;
Key_schedule	des_hash_key2;

int	des_hash_inited;

des_hash_init()

{
  if (des_hash_inited)
    return 0;
  des_set_key(hash_key1,&des_hash_key1);
  des_set_key(hash_key2,&des_hash_key2);
  des_hash_inited = 1;
  return 0;
}
