/*
  Author:  Pate Williams (c) 1997

  Modified-Rabin signature scheme. See "Handbook
  of Applied Cryptography" by Alfred J. Menezes
  et al pages 440 - 441.
*/

#include <stdio.h>
#include <string.h>
#include "lip.h"

#define DEBUG

void Rabin_gen_keys(long length, verylong *zd, verylong *zn)
{
  verylong za = 0, zb = 0, zp = 0, zq = 0;

  /* choose a prime p such that p mod 8 == 3 */
  do
    zrandomprime(length, 5l, &zp, zrandomb);
  while (zsmod(zp, 8l) != 3l);
  /* choose a prime q such that q mod 8 == 7 */
  do
    zrandomprime(length, 5l, &zq, zrandomb);
  while (zsmod(zq, 8l) != 7l);
  /* compute public key n*/
  zmul(zp, zq, zn);
  /* compute private key d = (n - p - q + 5) / 8 */
  zadd(zp, zq, &za);
  zsub(*zn, za, &zb);
  zsadd(zb, 5l, &za);
  zsdiv(za, 8l, zd);
  zfree(&za);
  zfree(&zb);
  zfree(&zp);
  zfree(&zq);
}

void Rabin_sign(char *buffer, long length, verylong zd,
                verylong zn, verylong *zs)
{
  long i, J;
  verylong za = 0, zb = 0, zc = 0, zm = 0;

  zintoz(buffer[0], &zc);
  for (i = 1; i < length; i++) {
    zsmul(zc, 256l, &za);
    zsadd(za, buffer[i], &zc);
  }
#ifdef DEBUG
  zwrite(zc);
  printf(" %ld\n", z2log(zc));
#endif
  zsmul(zc, 16l, &zb);
  zsadd(zb, 6l, &zm);
  J = zjacobi(zm, zn);
  if (J == 1)
    zexpmod(zm, zd, zn, zs);
  else if (J == - 1) {
    zrshift(zm, 1l, &za);
    zexpmod(za, zd, zn, zs);
  }
#ifdef DEBUG
  printf("J = %ld\n", J);
#endif
  zfree(&za);
  zfree(&zb);
  zfree(&zc);
  zfree(&zm);
}

int Rabin_verify(char *buffer, long *length, verylong zn, verylong zs)
{
  int value;
  long i, j, l, left, mod, number;
  verylong za = 0, zm = 0, zm1 = 0, zm2 = 0;

  zmulmod(zs, zs, zn, &zm1);
  mod = zsmod(zm1, 8l);
  if (mod == 6) zcopy(zm1, &zm2);
  else if (mod == 3) zlshift(zm1, 1l, &zm2);
  else if (mod == 7) zsub(zn, zm1, &zm2);
  else if (mod == 2) {
    zsub(zn, zm1, &za);
    zlshift(za, 1l, &zm2);
  }
  if (zsmod(zm2, 16l) == 6) {
    zsadd(zm2, - 6l, &zm1);
    zsdiv(zm1, 16l, &zm);
#ifdef DEBUG
    zwrite(zm);
    l = z2log(zm);
    printf(" %ld\n", l);
#endif
    number = l / 8l;
    i = 0;
    for (j = 0; j < number; j++) {
      zlowbits(zm, 8l, &za);
      buffer[i++] = (char) za[1];
      zrshift(zm, 8l, &za);
      zcopy(za, &zm);
    }
    left = l % 32;
    if (left) {
      zlowbits(zm, left, &za);
      buffer[i++] = (char) za[1];
    }
    *length = i;
    value = 1;
  }
  else
    value = 0;
  buffer[*length] = 0;
  strrev(buffer);
  zfree(&za);
  zfree(&zm);
  zfree(&zm1);
  zfree(&zm2);
  return value;
}

int main(void)
{
  char buffer[5][8] = {{1, 2, 3, 0},
                       {1, 2, 3, 4, 0},
                       {1, 2, 3, 4, 5, 0},
                       {1, 2, 3, 4, 5, 6, 0},
                       {1, 2, 3, 4, 5, 6, 7, 0}};
  char buffer1[5][8];
  long i, j, length;
  verylong zd = 0, zn = 0, zs = 0;

  zintoz(68l, &zd);
  zintoz(589l, &zn);
  buffer[0][0] = 12;
  Rabin_sign(buffer[0], 1, zd, zn, &zs);
  zwriteln(zs);
  printf(" %d\n", Rabin_verify(buffer1[0], &length, zn, zs));
  printf("%d\n", buffer1[0][0]);
  buffer[0][0] = 1;
  Rabin_gen_keys(64l, &zd, &zn);
  for (i = 0; i < 5; i++) {
    for (j = 0; j < strlen(buffer[i]); j++)
      printf("%d ", buffer[i][j]);
    printf("\n");
    Rabin_sign(buffer[i], strlen(buffer[i]), zd, zn, &zs);
    printf("%d ", Rabin_verify(buffer1[i], &length, zn, zs));
    printf("%d ", length);
    for (j = 0; j < length; j++)
      printf("%d ", buffer1[i][j]);
    printf("%d\n", strcmp(buffer[i], buffer1[i]));
  }
  return 0;
}
