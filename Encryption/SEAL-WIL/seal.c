/*
  Author:  Pate Williams (c) 1997

  SEAL (Software-optimized Encryption Algorithm).
  See "Handbook of Applied Cryptography" by Alfred
  J. Menezes et al 6.4.1 Section pages 213 - 216.
*/

#include <math.h>
#include <mem.h>
#include <stdio.h>
#include <stdlib.h>

#define DEBUG

typedef unsigned char uchar;
typedef unsigned long ulong;

struct SHA_1_struct {
  ulong A, B, C, D, E, H1, H2, H3, H4, H5;
};

ulong f(ulong u, ulong v, ulong w)
{
  return (u & v) | (~u & w);
}

ulong g(ulong u, ulong v, ulong w)
{
  return (u & v) | (u & w) | (v & w);
}

ulong h(ulong u, ulong v, ulong w)
{
  return u ^ v ^ w;
}

ulong LeftShift(ulong x, int number)
/* left circular shift number bits */
{
  return (x << number) | (x >> (32 - number));
}

ulong RightShift(ulong x, int number)
/* right circular shift number bits */
{
  return (x >> number) | (x << (32 - number));
}

void Round(int j_min, ulong y, ulong *X,
           struct SHA_1_struct *data,
           ulong (*z)(ulong, ulong, ulong))
{
  int j;
  ulong t;

  for (j = j_min; j < j_min + 20; j++) {
    t = LeftShift(data->A, 5) + z(data->B, data->C, data->D)
      + data->E + X[j] + y;
    data->E = data->D;
    data->D = data->C;
    data->C = LeftShift(data->B, 30);
    data->B = data->A;
    data->A = t;
  }
}

void SEAL_table_generation(ulong i, ulong *a, ulong *Gai)
{
  int j;
  static ulong y1 = 0x5a827999ul, y2 = 0x6ed9eba1ul,
               y3 = 0x8f1bbcdcul, y4 = 0xca62c1d6ul;
  struct SHA_1_struct data;
  ulong X[80];

  data.H1 = a[0];
  data.H2 = a[1];
  data.H3 = a[2];
  data.H4 = a[3];
  data.H5 = a[4];
  data.A = data.H1;
  data.B = data.H2;
  data.C = data.H3;
  data.D = data.H4;
  data.E = data.H5;
  memset(X, 0, 64);
  X[0] = i;
  for (j = 16; j < 80; j++)
    X[j] = LeftShift(X[j - 3] ^ X[j - 8] ^ X[j - 14] ^ X[j - 16], 1);
  Round( 0, y1, X, &data, f);
  Round(20, y2, X, &data, h);
  Round(40, y3, X, &data, g);
  Round(60, y4, X, &data, h);
  data.H1 += data.A;
  data.H2 += data.B;
  data.H3 += data.C;
  data.H4 += data.D;
  data.H5 += data.E;
  Gai[0] = data.H1;
  Gai[1] = data.H2;
  Gai[2] = data.H3;
  Gai[3] = data.H4;
  Gai[4] = data.H5;
}

void SEAL_initialize(ulong n, ulong l, ulong *A, ulong *B,
                     ulong *C, ulong *D, ulong *n1, ulong *n2,
                     ulong *n3, ulong *n4, ulong *R, ulong *T)
{
  ulong P, j, l4 = l * 4;

  *A = n ^ R[l4];
  *B = RightShift(n,  8) ^ R[l4 + 1];
  *C = RightShift(n, 16) ^ R[l4 + 2];
  *D = RightShift(n, 24) ^ R[l4 + 3];
  for (j = 0; j < 2; j++) {
    P = *A & 0x7fcul;
    *B += T[P / 4];
    *A = RightShift(*A, 9);
    P = *B & 0x7fcul;
    *C += T[P / 4];
    *B = RightShift(*B, 9);
    P = *C & 0x7fcul;
    *D += T[P / 4];
    *C = RightShift(*C, 9);
    P = *D & 0x7fcul;
    *A += T[P / 4];
    *D = RightShift(*D, 9);
  }
  *n1 = *D, *n2 = *B, *n3 = *A, *n4 = *C;
  P = *A & 0x7fcul;
  *B += T[P / 4];
  *A = RightShift(*A, 9);
  P = *B & 0x7fcul;
  *C += T[P / 4];
  *B = RightShift(*B, 9);
  P = *C & 0x7fcul;
  *D += T[P / 4];
  *C = RightShift(*C, 9);
  P = *D & 0x7fcul;
  *A += T[P / 4];
  *D = RightShift(*D, 9);
}

void SEAL(ulong *a, ulong n, ulong *y)
{
  ulong A, B, C, D, P, Q, i4, n1, n2, n3, n4, *p = y;
  ulong i, j, k, l, Gai[5], R[16], S[256], T[512];

  for (i = 0; i < 510; i += 5)
    SEAL_table_generation(i / 5, a, &T[i]);
  SEAL_table_generation(510 / 5, a, Gai);
  T[510] = Gai[0];
  T[511] = Gai[1];
  SEAL_table_generation((0x00001000ul - 1ul) / 5, a, Gai);
  for (j = 0; j < 4; j++)
    S[j] = Gai[j + 1];
  for (j = 4; j < 254; j += 5) {
    i = (0x00001000 + j) / 5;
    SEAL_table_generation(i, a, &S[j]);
  }
  SEAL_table_generation((254ul + 0x00001000) /5, a, Gai);
  S[254] = Gai[0];
  S[255] = Gai[1];
  SEAL_table_generation((0x00002000ul - 2) / 5, a, Gai);
  R[0] = Gai[2];
  R[1] = Gai[3];
  R[2] = Gai[4];
  for (k = 3; k < 13; k += 5) {
    i = (0x00002000 + k) / 5;
    SEAL_table_generation(i, a, &R[k]);
  }
  SEAL_table_generation((13 + 0x00002000ul) / 5, a, Gai);
  R[13] = Gai[0];
  R[14] = Gai[1];
  R[15] = Gai[2];
  for (l = 0; l < 4; l++) {
    SEAL_initialize(n, l, &A, &B, &C, &D, &n1, &n2, &n3, &n4, R, T);
    for (i = 0; i < 64; i++) {
      P = A & 0x7fcul;
      B += T[P / 4];
      A = RightShift(A, 9);
      B ^= A;
      Q = B & 0x7fcul;
      C ^= T[Q / 4];
      B = RightShift(B, 9);
      C += B;
      P = (P + C) & 0x7fcul;
      D += T[P / 4];
      C = RightShift(C, 9);
      D ^= C;
      Q = (Q + D) & 0x7fcul;
      A ^= T[Q / 4];
      D = RightShift(D, 9);
      A += D;
      P = (P + A) & 0x7fcul;
      B ^= T[P / 4];
      A = RightShift(A, 9);
      Q = (Q + B) & 0x7fcul;
      C += T[Q / 4];
      B = RightShift(B, 9);
      P = (P + C) & 0x7fcul;
      D ^= T[P / 4];
      C = RightShift(C, 9);
      Q = (Q + D) & 0x7fcul;
      A += T[Q / 4];
      D = RightShift(D, 9);
      i4 = i * 4;
      *p = B + S[i4], p++;
      *p = C ^ S[i4 + 1], p++;
      *p = D + S[i4 + 2], p++;
      *p = A ^ S[i4 + 3], p++;
      if (i & 1) {
        A += n3;
        C += n4;
      }
      else {
        A += n1;
        C += n2;
      }
    }
  }
  #ifdef DEBUG
  for (i = 0; i < 16; i++) {
    printf("%8x ", R[i]);
    if ((i + 1) % 6 == 0) printf("\n");
  }
  printf("\n\n");
  for (i = 0; i < 12; i++) {
    printf("%8x ", T[i]);
    if ((i + 1) % 6 == 0) printf("\n");
  }
  for (i = 506; i < 512; i++)
    printf("%8x ", T[i]);
  printf("\n\n");
  for (i = 0; i < 12; i++) {
    printf("%8x ", S[i]);
    if ((i + 1) % 6 == 0) printf("\n");
  }
  for (i = 250; i < 256; i++)
    printf("%8x ", S[i]);
  printf("\n\n");
  for (i = 0; i < 12; i++) {
    printf("%8x ", y[i]);
    if ((i + 1) % 6 == 0) printf("\n");
  }
  for (i = 1018; i < 1024; i++)
    printf("%8x ", y[i]);
  printf("\n\n");
  #endif
}

void main(void)
{
  ulong a[5] = {0x67452301, 0xefcdab89, 0x98badcfe,
                0x10325476, 0xc3d2e1f0}, y[1024];

  SEAL(a, 0x013577aful, y);
}