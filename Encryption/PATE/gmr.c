/*
  Author:  Pate Williams (c) 1997

  GMR one-time signature scheme. See "Handbook of
  Applied Cryptography" by Alfred J. Menezes et al
  11.6.4 Section pages 468 - 471. 11.101 Algorithm
  and 11.102 Algorithm page 469.
*/

#include <assert.h>
#include <malloc.h>
#include <math.h>
#include <stdio.h>
#include "lip.h"

void g0(verylong zx, verylong zn, verylong *zg)
{
  verylong zm = 0, zt = 0, zy = 0, zz = 0;

  zcopy(zn, &zt);
  zrshift(zt, 1l, &zm);
  zsq(zx, &zy);
  zmulmod(zx, zx, zn, &zz);
  if (zcompare(zz, zm) > 0) znegate(&zy);
  zmod(zy, zn, zg);
  zfree(&zm);
  zfree(&zt);
  zfree(&zy);
  zfree(&zz);
}

void g1(verylong zx, verylong zn, verylong *zg)
{
  verylong zm = 0, zt = 0, zy = 0, zz = 0;

  zcopy(zn, &zt);
  zrshift(zt, 1l, &zm);
  zsq(zx, &zy);
  zsmulmod(zy, 4l, zn, &zz);
  if (zcompare(zz, zm) > 0) znegate(&zy);
  zsmulmod(zy, 4l, zn, zg);
  zfree(&zm);
  zfree(&zt);
  zfree(&zy);
  zfree(&zz);
}

int main(void)
{
  long D[78], i = 0, j, n = 77, r = 15, t = 10, x;
  long m[10] = {1, 0, 1, 1, 0, 0, 0, 0, 1, 1};
  verylong zg = 0, zn = 0, zr = 0, zs = 0, zt = 0, zx = 0;
  verylong *zg0, *zg1, *zi0, *zi1;

  /* allocate the function and inverse arrays */
  zg0 = calloc(78, sizeof(verylong));
  zg1 = calloc(78, sizeof(verylong));
  assert(zg0 != 0 && zg1 != 0);
  zi0 = calloc(78, sizeof(verylong));
  zi1 = calloc(78, sizeof(verylong));
  assert(zi0 != 0 && zi1 != 0);
  /* fill in the function and inverse arrays */
  zintoz(n, &zn);
  for (x = 1; x <= n / 2; x++) {
    zintoz(x, &zx);
    if (zjacobi(zx, zn) == 1) {
      D[i] = x;
      g0(zx, zn, &zg0[i]);
      g1(zx, zn, &zg1[i]);
      j = ztoint(zg0[i]);
      zintoz(x, &zi0[j]);
      j = ztoint(zg1[i]);
      zintoz(x, &zi1[j]);
      i++;
    }
  }
  /* print out the function arrays */
  for (j = 0; j < i; j++) {
    printf("%2ld ", D[j]);
    printf("%2ld ", ztoint(zg0[j]));
    printf("%2ld ", ztoint(zg1[j]));
    printf("\n");
  }
  /* calculate the signature */
  zintoz(r, &zr);
  for (i = 0; i < t; i++) {
    if (m[i] == 0) {
      zcopy(zi0[ztoint(zr)], &zg);
      zcopy(zg, &zr);
    }
    else {
      zcopy(zi1[ztoint(zr)], &zg);
      zcopy(zg, &zr);
    }
    zwrite(zr); printf(" ");
  }
  printf("\nthe signature is ");
  zwriteln(zr);
  /* verify the signature */
  for (i = t - 1; i >= 0; i--) {
    if (m[i] == 0) {
      g0(zr, zn, &zg);
      zcopy(zg, &zr);
    }
    else {
      g1(zr, zn, &zg);
      zcopy(zg, &zr);
    }
    zwrite(zr); printf(" ");
  }
  printf("\nverification yields ");
  zwriteln(zr);
  free(zg0);
  free(zg1);
  free(zi0);
  free(zi1);
  zfree(&zg);
  zfree(&zn);
  zfree(&zr);
  zfree(&zs);
  zfree(&zt);
  zfree(&zx);
  return 0;
}
