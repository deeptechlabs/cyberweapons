/*
  Author:  Pate Williams (c) 1997

  The following program implements and tests the
  Blum-Blum-Shub random bits generator. The test
  suite is according to FIPS 140-1. See "Handbook
  of Applied Cryptography" by Alfred J. Menezes
  et al Section 5.4.4 pages 181 - 183 and 5.40
  Algorithm page 186.
*/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "lip.h"

#define BIT_STRING_LENGTH 20000l
#define MONOBIT_LO 9654l
#define MONOBIT_HI 10346l
#define POKER_LO 1.03
#define POKER_HI 57.4

void bbs_gen_key(long bit_length, verylong *zn, verylong *zx0)
/* generates the key and seed for the Blum-Blum-Shub
   random bits generator */
{
  long length = bit_length / 2;
  verylong zp = 0, zq = 0, zs = 0;

  zrstarts(time(NULL));
  zrandomprime(- length, 5l, &zp, zrandomb);
  zrandomprime(- length, 5l, &zq, zrandomb);
  zmul(zp, zq, zn);
  do zrandomb(*zn, &zs); while (zscompare(zs, 0l) == 0);
  zmulmod(zs, zs, *zn, zx0);
  zfree(&zp);
  zfree(&zq);
  zfree(&zs);
}

long bbs_next_bits(long number, verylong zn, verylong *zx)
/* gets number low order bits of x * x mod n */
{
  long low_bits;
  verylong zx0 = 0;

  zcopy(*zx, &zx0);
  zmulmod(zx0, zx0, zn, zx);
  zlowbits(*zx, number, &zx0);
  low_bits = zx0[1];
  zfree(&zx0);
  return low_bits;
}

int FIPS_140_1(char *bit_string)
/* Statistical tests for randomness returns - 3
   if bit_string fails monobit test, - 2 if it
   fails poker test, - 1 if it fails runs test,
   0 if it fails the long run test 1 otherwise */
{
  float X3, sum = 0.0;
  long B[6]= {0}, G[6] = {0}, n[16] = {0};
  long i, index, j, k, max_run = 0, n1 = 0;
  long interval_lo[6] = {2267, 1079, 502, 223, 90, 90};
  long interval_hi[6] = {2733, 1421, 748, 402, 223, 223};

  /* monobit test */
  for (i = 0; i < BIT_STRING_LENGTH; i++)
    if (bit_string[i] == 1) n1++;
  /* poker test */
  i = 0;
  k = BIT_STRING_LENGTH / 4;
  for (j = 0; j < k; j++) {
    index = 8 * bit_string[i + 3] + 4 * bit_string[i + 2]
          + 2 * bit_string[i + 1] + bit_string[i];
    n[index]++;
    i += 4;
  }
  for (i = 0; i < 16; i++) sum += n[i] * n[i];
  X3 = 16.0 * sum / k - k;
  /* runs test */
  i = 0;
  while (i < BIT_STRING_LENGTH) {
    j = 0;
    while (i < BIT_STRING_LENGTH && bit_string[i] == 1) i++, j++;
    if (j <= 6) B[j - 1]++; else B[5]++;
    if (j > max_run) max_run = j;
    while (i < BIT_STRING_LENGTH && bit_string[i] == 0) i++;
 }
  i = 0;
  while (i < BIT_STRING_LENGTH) {
    j = 0;
    while (i < BIT_STRING_LENGTH && bit_string[i] == 0) i++, j++;
    if (j <= 6) G[j - 1]++; else G[5]++;
    if (j > max_run) max_run = j;
    while (i < BIT_STRING_LENGTH && bit_string[i] == 1) i++;
  }
  /* print out results of the tests */
  printf("monobit statistic: %ld\n", n1);
  printf("poker test statistic: %lf\n", X3);
  printf("# blocks\tgaps\n");
  for (i = 0; i < 6; i++)
    printf("%ld %4ld\t\t%4ld\n", i + 1, B[i], G[i]);
  printf("long runs statistic: %ld\n", max_run);
  /* compute return value based on statistics */
  if (n1 <= MONOBIT_LO || n1 >= MONOBIT_HI) return - 3;
  if (X3 <= POKER_LO || X3 >= POKER_HI) return - 2;
  for (i = 0; i < 6; i++) {
    if (B[i] < interval_lo[i] || B[i] > interval_hi[i]) return - 1;
    if (G[i] < interval_lo[i] || G[i] > interval_hi[i]) return - 1;
  }
  if (max_run >= 34) return 0;
  return 1;
}

int main(void)
{
  char bit_string[BIT_STRING_LENGTH];
  long i;
  verylong zn = 0, zx0 = 0;

  /* fill the buffer to be tested */
  bbs_gen_key(256l, &zn, &zx0);
  for (i = 0; i < BIT_STRING_LENGTH; i++)
    bit_string[i] = (char) bbs_next_bits(1l, zn, &zx0);
  printf("value of FIPS_140_1 = %d\n", FIPS_140_1(bit_string));
  zfree(&zn);
  zfree(&zx0);
  return 0;
}
