

#include <stdio.h>
#include <time.h>
#include <string.h>
#include "speedc.h"

#define NO_OF_DATA 100000L

int main (int  argc, char *argv[]) 
{
  int  i;
  long int	total_bits;
  clock_t       clks;
  double        cpu_time;

  speed_key     key; 
  speed_data    pt, ct; 
  speed_idata   ipt; 
  speed_idata   ict; 
  speed_ikey    rndkey; 

  for (i=0; i<SPEED_KEY_LEN_BYTE; i++) {
    key[i] = 'a' + i;
  }

  for (i=0; i<8; i++) {
    ipt[i] = '0'+i;
  }

  /* reset the clock */
  clock();

  speed_key_schedule(key, rndkey);


  for (i=0; i<NO_OF_DATA; i++) {
    speed_encrypt_rk (ipt, ict, rndkey);
    /* 
    speed_encrypt (pt, ct, key);
    */
  }

  /* get the number clocks */
  clks = clock();
  /* get cpu time */
  cpu_time = (double)clks / (double)CLOCKS_PER_SEC;

  total_bits = NO_OF_DATA * SPEED_DATA_LEN;

  if (cpu_time > 0.0) {
    printf ("Length of data  = %3d bits\n", SPEED_DATA_LEN);
    printf ("Length of key   = %3d bits\n", SPEED_KEY_LEN);
    printf ("No. of rounds   = %3d \n",     SPEED_NO_OF_RND);
    printf ("clock ticks     = %d\n", clks);
    printf ("clock ticks/sec = %d\n", CLOCKS_PER_SEC);
    printf ("CPU Time        = %4.2f seconds\n", cpu_time);
    printf ("No. of bits     = %d\n", total_bits);
    printf ("Throughput      = %4.2f megabit/second\n",
    (double)total_bits/(1.0E6 * cpu_time));
    printf ("                = %4.2f bit/clock\n",
    (double)total_bits/(double)clks);
    printf ("--------------------------------------------------\n");
  } else {
    printf ("not enough blocks !\n");
  }
}


