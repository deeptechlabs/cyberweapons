/*
  Author:  Pate Williams (c) 1997

  FEAL-8. Fast Data Encipherment Algorithm.
  See "Handbook of Applied Cryptography" by
  Alfred J. Menezes et al 7.5 Section pages
  259 - 262.
*/

#include <stdio.h>

long Sd(long d, long x, long y)
{
  long sum = ((x + y + d) % 256) << 2;

  return (sum | ((sum & 768) >> 8)) & 255;
}

void f(long *A, long *Y, long *U)
{
  long t1 = (A[0] ^ A[1]) ^ Y[0];
  long t2 = (A[2] ^ A[3]) ^ Y[1];

  U[1] = Sd(1, t1, t2);
  U[2] = Sd(0, t2, U[1]);
  U[0] = Sd(0, A[0], U[1]);
  U[3] = Sd(1, A[3], U[2]);
}

void fK(long *A, long *B, long *U)
{
  long t1 = A[0] ^ A[1];
  long t2 = A[2] ^ A[3];

  U[1] = Sd(1, t1, t2 ^ B[0]);
  U[2] = Sd(0, t2, U[1] ^ B[1]);
  U[0] = Sd(0, A[0], U[1] ^ B[2]);
  U[3] = Sd(1, A[3], U[2] ^ B[3]);
}

void FEAL_key_schedule(long key0, long key1, long *K)
{
  long i, j, i2, U[4], U0[4], U1[4], U2[4], V[4];

  for (i = 0; i < 4; i++) U2[i] = 0;
  U1[0] = key0 >> 24;
  U1[1] = key0 >> 16;
  U1[2] = key0 >>  8;
  U1[3] = key0 & 255;
  U0[0] = key1 >> 24;
  U0[1] = key1 >> 16;
  U0[2] = key1 >>  8;
  U0[3] = key1 & 255;
  for (i = 1; i <= 8; i++) {
    for (j = 0; j < 4; j++)
      V[j] = U0[j] ^ U2[j];
    fK(U1, V, U);
    i2 = 2 * i;
    K[i2 - 2] = (U[0] << 8) | U[1];
    K[i2 - 1] = (U[2] << 8) | U[3];
    for (j = 0; j < 4; j++) U2[j] = U1[j];
    for (j = 0; j < 4; j++) U1[j] = U0[j];
    for (j = 0; j < 4; j++) U0[j] = U[j];
  }
}

void FEAL_encryption(long M0, long M1,
                     long *C0, long *C1, long *K)
{
  long i, j, L, L8, ML, MR, R, R8;
  long L0[4], L1[4], R0[4], R1[4], U[4], Y[2];

  ML = M0, MR = M1;
  L = ML ^ ((K[8]  << 16) | K[9]);
  R = MR ^ ((K[10] << 16) | K[11]);
  R ^= L;
  L0[0] = L >> 24;
  L0[1] = L >> 16;
  L0[2] = L >>  8;
  L0[3] = L & 255;
  R0[0] = R >> 24;
  R0[1] = R >> 16;
  R0[2] = R >>  8;
  R0[3] = R & 255;
  for (i = 0; i < 8; i++) {
    for (j = 0; j < 4; j++) L1[j] = R0[j];
    Y[0] = K[i] >> 8;
    Y[1] = K[i] & 255;
    f(R0, Y, U);
    for (j = 0; j < 4; j++) {
      R1[j] = (L0[j] ^ U[j]) & 255;
      L0[j] = L1[j];
      R0[j] = R1[j];
    }
  }
  L8  = L1[0] << 24;
  L8 |= L1[1] << 16;
  L8 |= L1[2] <<  8;
  L8 |= L1[3] & 255;
  R8  = R1[0] << 24;
  R8 |= R1[1] << 16;
  R8 |= R1[2] <<  8;
  R8 |= R1[3] & 255;
  L8 ^= R8;
  L8 ^= (K[14] << 16) | K[15];
  R8 ^= (K[12] << 16) | K[13];
  *C0 = R8;
  *C1 = L8;
}

void FEAL_decryption(long C0, long C1,
                     long *M0, long *M1, long *K)
{
  long i, j, L, L8, ML, MR, R, R8;
  long L0[4], L1[4], R0[4], R1[4], U[4], Y[2];

  ML = C0, MR = C1;
  L = ML ^ ((K[12] << 16) | K[13]);
  R = MR ^ ((K[14] << 16) | K[15]);
  R ^= L;
  L0[0] = L >> 24;
  L0[1] = L >> 16;
  L0[2] = L >>  8;
  L0[3] = L & 255;
  R0[0] = R >> 24;
  R0[1] = R >> 16;
  R0[2] = R >>  8;
  R0[3] = R & 255;
  for (i = 7; i >= 0; i--) {
    for (j = 0; j < 4; j++) L1[j] = R0[j];
    Y[0] = K[i] >> 8;
    Y[1] = K[i] & 255;
    f(R0, Y, U);
    for (j = 0; j < 4; j++) {
      R1[j] = (L0[j] ^ U[j]) & 255;
      L0[j] = L1[j];
      R0[j] = R1[j];
    }
  }
  L8  = L1[0] << 24;
  L8 |= L1[1] << 16;
  L8 |= L1[2] <<  8;
  L8 |= L1[3] & 255;
  R8  = R1[0] << 24;
  R8 |= R1[1] << 16;
  R8 |= R1[2] <<  8;
  R8 |= R1[3] & 255;
  L8 ^= R8;
  R8 ^= (K[8]  << 16) | K[9];
  L8 ^= (K[10] << 16) | K[11];
  *M0 = R8;
  *M1 = L8;
}

void main(void)
{
  long C0, C1, i;
  long key0 = 0x01234567, key1 = 0x89abcdef;
  long K[16], M0 = 0, M1 = 0;

  FEAL_key_schedule(key0, key1, K);
  for (i = 0; i < 16; i++)
    printf("%4x\n", K[i]);
  FEAL_encryption(M0, M1, &C0, &C1, K);
  printf("%x %x\n", C0, C1);
  FEAL_decryption(C0, C1, &M0, &M1, K);
  printf("%x %x\n", M0, M1);
}