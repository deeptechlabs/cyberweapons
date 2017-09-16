/*
  Author:  Pate Williams (c) 1997

  Merkle-Hellman knapsack encryption. See "Handbook
  of Applied Cryptography" by Alfred J. Menezes et
  al Section 8.6.1 pages 300 - 302.
*/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "lip.h"

#define DEBUG

void MH_gen_keys(long n, verylong zB, long *pi,
                 verylong *zM, verylong *zW,
                 verylong *za, verylong *zb)
/* Merkle Hellman knapsack key generation */
{
  int found;
  long i, j, p, s;
  verylong zc = 0, zd = 0, zs = 0;

  /* initialize the psuedo random number generators */
  srand(time(NULL));
  zrstarts(time(NULL));
  /* find a superincreasing sequence b[i] */
  zzero(zM);
  do zrandomb(zB, &zb[0]); while (zscompare(zb[0], 0l) == 0);
  for (i = 1; i < n; i++) {
    zzero(&zs);
    for (j = 0; j < i; j++) {
      zadd(zs, zb[j], &zc);
      zcopy(zc, &zs);
    }
    do s = rand(); while (s == 0);
    zsadd(zs, s, &zc);
    zcopy(zc, &zb[i]);
    zadd(*zM, zc, &zs);
    zcopy(zs, zM);
  }
  do s = rand(); while (s == 0);
  zsadd(*zM, s, &zc);
  zcopy(zc, zM);
  /* select a random integer 1 <= W <= M - 1 such
     that gcd(W, M) = 1 */
  do {
    do zrandomb(*zM, zW); while (zscompare(*zW, 0l) == 0);
    zgcd(*zW, *zM, &zd);
  } while (zscompare(zd, 1l) != 0);
  /* select a random permutation of 0, 1, ..., n - 1 */
  for (i = 0; i < n; i++) {
    do {
      found = 0;
      p = rand() % n;
      for (j = 0; j < i && !found; j++)
        found = p == pi[j];
    } while (found);
    pi[i] = p;
  }
  /* compute the public key */
  for (i = 0; i < n; i++)
    zmulmod(*zW, zb[pi[i]], *zM, &za[i]);
  zfree(&zc);
  zfree(&zd);
  zfree(&zs);
}

void MH_encryption(char *m, long n, verylong *za,
                   verylong *zc)
/* m consists of n message bits one per character */
{
  long i;
  verylong zb = 0, zd = 0;

  zzero(zc);
  for (i = 0; i < n; i++) {
    zsmul(za[i], m[i], &zb);
    zadd(*zc, zb, &zd);
    zcopy(zd, zc);
  }
  zfree(&zb);
  zfree(&zd);
}

void Solve(char *x, long n, verylong zs, verylong *zb)
/* solves a superincreasing subset sum problem */
{
  long i;
  verylong za = 0, zt = 0;

  zcopy(zs, &zt);
  i = n - 1;
  while (i >= 0) {
    if (zcompare(zt, zb[i]) >= 0) {
      x[i] = 1;
      zsub(zt, zb[i], &za);
      zcopy(za, &zt);
    }
    else x[i] = 0;
    i--;
  }
  zfree(&za);
  zfree(&zt);
}

void MH_decryption(char *m, char *r, long n, long *pi,
                   verylong zc, verylong zM,
                   verylong zW, verylong *zb)
{
  long i;
  verylong za = 0, zd = 0;

  zinvmod(zW, zM, &za);
  zmulmod(za, zc, zM, &zd);
  Solve(r, n, zd, zb);
  for (i = 0; i < n; i++) m[i] = r[pi[i]];
}

int main(void)
{
  char m[8] = {1, 0, 1, 0, 1, 0, 1, 0}, r[8];
  long i, n = 8, pi[8];
  verylong zB = 0, zM = 0, zW = 0, zc = 0;
  verylong za[8], zb[8];

  zintoz(1024l, &zB);
  for (i = 0; i < n; i++) {
    za[i] = zb[i] = 0;
    printf("%d", m[i]);
  }
  printf("\n");
  MH_gen_keys(n, zB, pi, &zM, &zW, za, zb);
  #ifdef DEBUG
  zwriteln(zM);
  zwriteln(zW);
  for (i = 0; i < n; i++) {
    zwrite(zb[i]); printf(" ");
  }
  printf("\n");
  #endif
  MH_encryption(m, n, za, &zc);
  MH_decryption(m, r, n, pi, zc, zM, zW, zb);
  for (i = 0; i < n; i++) {
    zfree(&za[i]);
    zfree(&zb[i]);
    printf("%d", m[i]);
  }
  printf("\n");
  zfree(&zB);
  zfree(&zM);
  zfree(&zW);
  zfree(&zc);
  return 0;
}
