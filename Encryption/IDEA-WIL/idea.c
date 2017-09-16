/*
  Author:  Pate Williams (c) 1997

  IDEA (International Data Encryption Algorithm).
  See "Handbook of Applied Cryptography" by Alfred
  J. Menezes et al 7.6 Section pages 263 - 266.
*/

#include <stdio.h>
#include <stdlib.h>

#define DEBUG

typedef unsigned long ulong;
typedef unsigned short ushort;

ushort add(long a, long b)
{
  return (ushort)((a + b) % 65536l);
}

ushort multiply(long a, long b)
{
  long ch, cl, c;

  if (a == 0) a = 65536l;
  if (b == 0) b = 65536l;
  c = a * b;
  if (c) {
    ch = (c >> 16) & 65535l;
    cl = c & 65535l;
    if (cl >= ch) return (ushort) (cl - ch);
    return (ushort) ((cl - ch + 65537l) & 65535l);
  }
  if (a == b) return 1;
  return 0;
}

void IDEA_encryption(ushort *X, ushort *Y, long **K)
{
  ushort a, i, r, t0, t1, t2;

  for (r = 0; r < 8; r++) {
    X[0] = multiply(X[0], K[r][0]);
    X[3] = multiply(X[3], K[r][3]);
    X[1] = add(X[1], K[r][1]);
    X[2] = add(X[2], K[r][2]);
    t0 = multiply(K[r][4], X[0] ^ X[2]);
    t1 = multiply(K[r][5], add(t0, X[1] ^ X[3]));
    t2 = add(t0, t1);
    X[0] ^= t1;
    X[3] ^= t2;
    a = X[1] ^ t2;
    X[1] = X[2] ^ t1;
    X[2] = a;
    #ifdef DEBUG
    printf("%u ", r + 1);
    for (i = 0; i < 6; i++)
      printf("%4x ", (ushort) K[r][i]);
    printf("%4x %4x %4x %4x\n", X[0], X[1], X[2], X[3]);
    #endif
  }
  Y[0] = multiply(X[0], K[8][0]);
  Y[3] = multiply(X[3], K[8][3]);
  Y[1] = add(X[2], K[8][1]);
  Y[2] = add(X[1], K[8][2]);
  #ifdef DEBUG
  printf("9 ");
  for (i = 0; i < 6; i++)
    printf("%4x ", (ushort) K[8][i]);
  printf("%4x %4x %4x %4x\n", Y[0], Y[1], Y[2], Y[3]);
  #endif
}

ushort bits_to_ushort(ushort *bits)
{
  ushort i, value = bits[0];

  for (i = 1; i < 16; i++)
    value = (ushort) ((value << 1) + bits[i]);
  return value;
}

void ushort_to_bits(ushort number, ushort *bits)
{
  ushort i, temp[16];

  for (i = 0; i < 16; i++) {
    temp[i] = (ushort) (number & 1);
    number >>= 1;
  }
  for (i = 0; i < 16; i++)
    bits[i] = temp[15 - i];
}

void cyclic_left_shift(ushort index, ushort *bits1,
                       ushort *bits2, long **K)
{
  ushort i, j;

  if (index == 0) {
    for (i = 0; i < 6; i++)
      ushort_to_bits((ushort) K[0][i], bits1 + 16 * i);
    ushort_to_bits((ushort) K[1][0], bits1 + 96);
    ushort_to_bits((ushort) K[1][1], bits1 + 112);
  }
  i = 0;
  for (j = 25; j < 128; j++)
    bits2[i++] = bits1[j];
  for (j = 0; j < 25; j++)
    bits2[i++] = bits1[j];
  switch (index) {
    case 0 :
      for (i = 2; i < 6; i++)
        K[1][i] = bits_to_ushort(bits2 + 16 * (i - 2));
      for (i = 0; i < 4; i++)
        K[2][i] = bits_to_ushort(bits2 + 64 + 16 * i);
      break;
    case 1 :
      K[2][4] = bits_to_ushort(bits2);
      K[2][5] = bits_to_ushort(bits2 + 16);
      for (i = 0; i < 6; i++)
        K[3][i] = bits_to_ushort(bits2 + 32 + 16 * i);
      break;
    case 2 :
      for (i = 0; i < 6; i++)
        K[4][i] = bits_to_ushort(bits2 + 16 * i);
      K[5][0] = bits_to_ushort(bits2 + 96);
      K[5][1] = bits_to_ushort(bits2 + 112);
      break;
    case 3 :
      for (i = 2; i < 6; i++)
        K[5][i] = bits_to_ushort(bits2 + 16 * (i - 2));
      for (i = 0; i < 4; i++)
        K[6][i] = bits_to_ushort(bits2 + 64 + 16 * i);
      break;
    case 4 :
      K[6][4] = bits_to_ushort(bits2);
      K[6][5] = bits_to_ushort(bits2 + 16);
      for (i = 0; i < 6; i++)
        K[7][i] = bits_to_ushort(bits2 + 32 + 16 * i);
      break;
    case 5 :
      for (i = 0; i < 4; i++)
        K[8][i] = bits_to_ushort(bits2 + 16 * i);
      break;
  }
}

void IDEA_encryption_key_schedule(ushort *key, long **K)
{
  ushort bits1[128], bits2[128], i;

  for (i = 0; i < 6; i++) K[0][i] = key[i];
  K[1][0] = key[6], K[1][1] = key[7];
  cyclic_left_shift(0, bits1, bits2, K);
  cyclic_left_shift(1, bits2, bits1, K);
  cyclic_left_shift(2, bits1, bits2, K);
  cyclic_left_shift(3, bits2, bits1, K);
  cyclic_left_shift(4, bits1, bits2, K);
  cyclic_left_shift(5, bits2, bits1, K);
}

void extended_euclidean(long a, long b, long *x, long *y, long *d)
{
  long q, r, x1, x2, y1, y2;

  if (b == 0) {
    *d = a, *x = 1, *y = 0;
    return;
  }
  x2 = 1, x1 = 0, y2 = 0, y1 = 1;
  while (b > 0) {
    q = a / b, r = a - q * b;
    *x = x2 - q * x1;
    *y = y2 - q * y1;
    a = b, b = r, x2 = x1, x1 = *x, y2 = y1, y1 = *y;
  }
  *d = a, *x = x2, *y = y2;
}

long inv(ushort ub)
{
  long d, a = 65537l, b = ub, x, y;

  if (ub == 0) return 65536l;
  extended_euclidean(a, b, &x, &y, &d);
  if (y >= 0) return (ushort) y;
  return (ushort) (y + 65537l);
}

void IDEA_decryption_key_schedule(long **K, long **L)
{
  ushort r, r8, r9;

  L[0][0] = inv((ushort) K[8][0]);
  L[0][1] = - K[8][1];
  L[0][2] = - K[8][2];
  L[0][3] = inv((ushort) K[8][3]);
  L[0][4] =  K[7][4];
  L[0][5] =  K[7][5];
  for (r = 1; r < 8; r++) {
    r9 = (ushort) (8 - r);
    r8 = (ushort) (7 - r);
    L[r][0] = inv((ushort) K[r9][0]);
    L[r][1] = - K[r9][2];
    L[r][2] = - K[r9][1];
    L[r][3] = inv((ushort) K[r9][3]);
    L[r][4] = K[r8][4];
    L[r][5] = K[r8][5];
  }
  L[8][0] = inv((ushort) K[0][0]);
  L[8][1] = - K[0][1];
  L[8][2] = - K[0][2];
  L[8][3] = inv((ushort) K[0][3]);
  L[8][4] = L[8][6] = 0;
}

void main(void)
{
  long **K, **L;
  ushort i, j, key[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  ushort X[4] = {0, 1, 2, 3}, Y[4];

  K = calloc(9, sizeof(long *));
  L = calloc(9, sizeof(long *));
  for (i = 0; i < 9; i++) {
    K[i] = calloc(6, sizeof(long));
    L[i] = calloc(6, sizeof(long));
    for (j = 0; j < 6; j++) K[i][j] = L[i][j] = 0;
  }
  IDEA_encryption_key_schedule(key, K);
  IDEA_encryption(X, Y, K);
  IDEA_decryption_key_schedule(K, L);
  IDEA_encryption(Y, X, L);
  for (i = 0; i < 9; i++) {
    free(K[i]);
    free(L[i]);
  }
  free(K);
  free(L);
}