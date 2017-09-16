
#include <stdio.h>
#include <string.h>
#include "speedc.h"


#if   SPEED_DATA_LEN == 256
#define F_WD_MASK       0x0FFFFFFFFL
#define H_WD_MASK       0x0FFFF
#elif SPEED_DATA_LEN == 128
#define F_WD_MASK       0x0FFFF
#define H_WD_MASK       0x0FF
#else /* SPEED_DATA_LEN == 64 */
#define F_WD_MASK       0x0FF
#define H_WD_MASK       0x0F
#endif


int main (int  argc, char *argv[])
{

  int           i, j, k;
  speed_key     key; 
  speed_data    pt, pt2; 
  speed_data    ct, ct2; 

  for (i=0; i<SPEED_DATA_LEN_BYTE; i++) {
    pt[i] = i;
  }

  for (i=0; i<SPEED_KEY_LEN_BYTE; i++) {
    key[i] = 'A' + i;
  }

  speed_encrypt(pt, ct, key);
  speed_decrypt(pt2, ct, key);

  printf ("SPEED_DATA_LEN = %d, SPEED_KEY_LEN = %d, SPEED_NO_OF_RND = %d\n",
           SPEED_DATA_LEN, SPEED_KEY_LEN, SPEED_NO_OF_RND);

  printf ("key        = ");
  for (i=0; i<SPEED_KEY_LEN_BYTE; i++) {
    printf ("%02X ", key[SPEED_KEY_LEN_BYTE-1-i]);
    if (i+1 ==16) printf ("\n             ");
  }
  printf ("\n");

  printf ("plaintext  = ");
  for (i=0; i< SPEED_DATA_LEN_BYTE; i++) {
    printf ("%02X ", pt[SPEED_DATA_LEN_BYTE - 1 -i]);
    if (i+1 ==16) printf ("\n             ");
  }
  printf ("\n");

  printf ("ciphertext = ");
  for (i=0; i< SPEED_DATA_LEN_BYTE; i++) {
    printf ("%02X ", ct[SPEED_DATA_LEN_BYTE - 1 -i]);
    if (i+1 ==16) printf ("\n             ");
  }
  printf ("\n");

  printf ("plaintext' = ");
  for (i=0; i< SPEED_DATA_LEN_BYTE; i++) {
    printf ("%02X ", pt2[SPEED_DATA_LEN_BYTE - 1 -i]);
    if (i+1 ==16) printf ("\n             ");
  }
  printf ("\n");
  printf ("----------------------\n");

  return (0);

}

