/*
  Author:  Pate Williams (c) 1997

  The following program implements and tests the
  Micali-Schnorr random bits generator. The test
  suite is according to FIPS 140-1. See "Handbook
  of Applied Cryptography" by Alfred J. Menezes
  et al Section 5.4.4 pages 181 - 183 and 5.37
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

void Micali_Schnorr_gen_key(long bit_length, verylong *ze,
                            verylong *zn, verylong *zx0,
                            long *k, long *r)
/* generates the key and seed for the Micali-Schnorr
   pseudorandom bits generator */
{
  long length = bit_length / 2, N;
  verylong zd = 0, zp = 0, zq = 0, zs = 0, zt = 0;
  verylong zphi = 0;

  zrstarts(time(NULL));
  zrandomprime(length, 5l, &zp, zrandomb);
  zrandomprime(length, 5l, &zq, zrandomb);
  zmul(zp, zq, zn);
  zsadd(zp, - 1l, &zs);
  zsadd(zq, - 1l, &zt);
  zmul(zs, zt, &zphi);
  N = z2log(*zn);
  zpstart();
  do {
    zintoz(zpnext(), ze);
    zgcd(*ze, zphi, &zd);
    zsmul(*ze, 80l, &zs);
  } while (zscompare(zd, 1l) != 0 && zscompare(zs, N) > 0);
  *k = N * (1.0 - 2 / (double) ztoint(*ze));
  *r = N - *k;
  zrandomprime(*r, 5l, zx0, zrandomb);
  zfree(&zd);
  zfree(&zp);
  zfree(&zq);
  zfree(&zs);
  zfree(&zt);
  zfree(&zphi);
}

void Micali_Schnorr_next_bits(long k, long r, verylong ze,
                              verylong zn, verylong *zx,
                              verylong *zz)
/* gets the next bits in the sequence */
{
  verylong zx0 = 0, zy = 0;

  zcopy(*zx, &zx0);
  zexpmod(zx0, ze, zn, &zy);
  zhighbits(zy, r, zx);
  zlowbits(zy, k, zz);
  zfree(&zx0);
  zfree(&zy);
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
  long i = 0, j, k, r;
  verylong ze = 0, zn = 0, zx = 0, zy = 0, zz = 0;

  /* fill the buffer to be tested */
  Micali_Schnorr_gen_key(256l, &ze, &zn, &zx, &k, &r);
  printf("%ld %ld\n", k, r);
  zwriteln(zx);
  while (i < BIT_STRING_LENGTH) {
    Micali_Schnorr_next_bits(k, r, ze, zn, &zx, &zz);
    for (j = 0; j < k; j++) {
      zlowbits(zz, 1l, &zy);
      if (i < BIT_STRING_LENGTH)
        bit_string[i++] = (char) ztoint(zy);
      zrshift(zz, 1l, &zy);
      zcopy(zy, &zz);
    }
  }
  printf("value of FIPS_140_1 = %d\n", FIPS_140_1(bit_string));
  zfree(&ze);
  zfree(&zn);
  zfree(&zx);
  zfree(&zy);
  zfree(&zz);
  return 0;
}
