/*
  Author:  Pate Williams (c) 1997

  9.41 Algorithm Matyas-Meyer-Oseas hash
  See "Handbook of Applied Cryptography"
  by Alfred J. Menezes et al page 341.
  The message to be hashed is assumed to
  have a bitlength that is a multiple of
  eight bits.
*/

#include <mem.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define BITS_PER_LONG 32
#define BYTES_PER_BLOCK 8
#define LOG_N_BYTES 3
#define SHIFT 5
#define ROUNDS 16

/* define the required tables */
char IP[64] = {58, 50, 42, 34, 26, 18, 10, 2,
               60, 52, 44, 36, 28, 20, 12, 4,
               62, 54, 46, 38, 30, 22, 14, 6,
               64, 56, 48, 40, 32, 24, 16, 8,
               57, 49, 41, 33, 25, 17,  9, 1,
               59, 51, 43, 35, 27, 19, 11, 3,
               61, 53, 45, 37, 29, 21, 13, 5,
               63, 55, 47, 39, 31, 23, 15, 7},
/* inverse permutation table */
    IPI[64] = {40, 8, 48, 16, 56, 24, 64, 32,
               39, 7, 47, 15, 55, 23, 63, 31,
               38, 6, 46, 14, 54, 22, 62, 30,
               37, 5, 45, 13, 53, 21, 61, 29,
               36, 4, 44, 12, 52, 20, 60, 28,
               35, 3, 43, 11, 51, 19, 59, 27,
               34, 2, 42, 10, 50, 18, 58, 26,
               33, 1, 41,  9, 49, 17, 57, 25},
E[48] = {32,  1,  2,  3,  4,  5,
          4,  5,  6,  7,  8,  9,
          8,  9, 10, 11, 12, 13,
         12, 13, 14, 15, 16, 17,
         16, 17, 18, 19, 20, 21,
         20, 21, 22, 23, 24, 25,
         24, 25, 26, 27, 28, 29,
         28, 29, 30, 31, 32,  1},
P[32] = {16,  7, 20, 21,
         29, 12, 28, 17,
          1, 15, 23, 26,
          5, 18, 31, 10,
          2,  8, 24, 14,
         32, 27,  3,  9,
         19, 13, 30,  6,
         22, 11,  4, 25},
S[8][4][16] = {{{14,  4, 13,  1,  2, 15, 11,  8,
                  3, 10,  6, 12,  5,  9,  0,  7},
                { 0, 15,  7,  4, 14,  2, 13,  1,
                 10,  6, 12, 11,  9,  5,  3,  8},
                { 4,  1, 14,  8, 13,  6,  2, 11,
                 15, 12,  9,  7,  3, 10,  5,  0},
                {15, 12,  8,  2,  4,  9,  1,  7,
                  5, 11,  3, 14, 10,  0,  6, 13}},
               {{15,  1,  8, 14,  6, 11,  3,  4,
                  9,  7,  2, 13, 12,  0,  5, 10},
                { 3, 13,  4,  7, 15,  2,  8, 14,
                 12,  0,  1, 10,  6,  9, 11,  5},
                { 0, 14,  7, 11, 10,  4, 13,  1,
                  5,  8, 12,  6,  9,  3,  2, 15},
                {13,  8, 10,  1,  3, 15,  4,  2,
                 11,  6,  7, 12,  0,  5, 14,  9}},
               {{10,  0,  9, 14,  6,  3, 15,  5,
                  1, 13, 12,  7, 11,  4,  2,  8},
                {13,  7,  0,  9,  3,  4,  6, 10,
                  2,  8,  5, 14, 12, 11, 15,  1},
                {13,  6,  4,  9,  8, 15,  3,  0,
                 11,  1,  2, 12,  5, 10, 14,  7},
                { 1, 10, 13,  0,  6,  9,  8,  7,
                  4, 15, 14,  3, 11,  5,  2, 12}},
               {{ 7, 13, 14,  3,  0,  6,  9, 10,
                  1,  2,  8,  5, 11, 12,  4, 15},
                {13,  8, 11,  5,  6, 15,  0,  3,
                  4,  7,  2, 12,  1, 10, 14,  9},
                {10,  6,  9,  0, 12, 11,  7, 13,
                 15,  1,  3, 14,  5,  2,  8,  4},
                { 3, 15,  0,  6, 10,  1, 13,  8,
                  9,  4,  5, 11, 12,  7,  2, 14}},
               {{ 2, 12,  4,  1,  7, 10, 11,  6,
                  8,  5,  3, 15, 13,  0, 14,  9},
                {14, 11,  2, 12,  4,  7, 13,  1,
                  5,  0, 15, 10,  3,  9,  8,  6},
                { 4,  2,  1, 11, 10, 13,  7,  8,
                 15,  9, 12,  5,  6,  3,  0, 14},
                {11,  8, 12,  7,  1, 14,  2, 13,
                  6, 15,  0,  9, 10,  4,  5,  3}},
               {{12,  1, 10, 15,  9,  2,  6,  8,
                  0, 13,  3,  4, 14,  7,  5, 11},
                {10, 15,  4,  2,  7, 12,  9,  5,
                  6,  1, 13, 14,  0, 11,  3,  8},
                { 9, 14, 15,  5,  2,  8, 12,  3,
                  7,  0,  4, 10,  1, 13, 11,  6},
                { 4,  3,  2, 12,  9,  5, 15, 10,
                 11, 14,  1,  7,  6,  0,  8, 13}},
               {{ 4, 11,  2, 14, 15,  0,  8, 13,
                  3, 12,  9,  7,  5, 10,  6,  1},
                {13,  0, 11,  7,  4,  9,  1, 10,
                 14,  3,  5, 12,  2, 15,  8,  6},
                { 1,  4, 11, 13, 12,  3,  7, 14,
                 10, 15,  6,  8,  0,  5,  9,  2},
                { 6, 11, 13,  8,  1,  4, 10,  7,
                  9,  5,  0, 15, 14,  2,  3, 12}},
               {{13,  2,  8,  4,  6, 15, 11,  1,
                 10,  9,  3, 14,  5,  0, 12,  7},
                { 1, 15, 13,  8, 10,  3,  7,  4,
                 12,  5,  6, 11,  0, 14,  9,  2},
                { 7, 11,  4,  1,  9, 12, 14,  2,
                  0,  6, 10, 13, 15,  3,  5,  8},
                { 2,  1, 14,  7,  4, 10,  8, 13,
                 15, 12,  9,  0,  3,  5,  6, 11}}},
PC1_C[28] = {57, 49, 41, 33, 25, 17,  9,
              1, 58, 50, 42, 34, 26, 18,
             10,  2, 59, 51, 43, 35, 27,
             19, 11,  3, 60, 52, 44, 36},
PC1_D[28] = {63, 55, 47, 39, 31, 23, 15,
              7, 62, 54, 46, 38, 30, 22,
             14,  6, 61, 53, 45, 37, 29,
             21, 13,  5, 28, 20, 12,  4},
PC2[48] = {14, 17, 11, 24,  1,  5,
            3, 28, 15,  6, 21, 10,
           23, 19, 12,  4, 26,  8,
           16,  7, 27, 20, 13,  2,
           41, 52, 31, 37, 47, 55,
           30, 40, 51, 45, 33, 48,
           44, 49, 39, 56, 34, 53,
           46, 42, 50, 36, 29, 32};

long get_bit(int bit_number, long *buffer)
{
  int long_number = (bit_number - 1) >> SHIFT, shift;

  shift = bit_number <= 32 ? BITS_PER_LONG - bit_number :
          64 - bit_number;
  return ((buffer[long_number] >> shift) & 1L);
}

void set_bit(int bit_number, long value, long *buffer)
{
  int long_number = (bit_number - 1) >> SHIFT, shift;
  long mask;

  shift = bit_number <= 32 ? BITS_PER_LONG - bit_number :
          64 - bit_number;
  if (value == 1)
    buffer[long_number] |= 1L << shift;
  else {
    mask = 1L << shift;
    buffer[long_number] &= ~mask;
  }
}

long left_shift_28(long C, int count)
{
  long mask1 = 1;
  long mask3 = 3;
  long nibble;

  if (count == 1)
    nibble = (C >> (32 - count)) & mask1;
  else
    nibble = (C >> (32 - count)) & mask3;
  return (0xfffffff0 & (C << count)) | (nibble << 4);
}

void DES_key_schedule(long K[ROUNDS][2], long key[2])
{
  int i, i1, i3, j, k, v[ROUNDS];
  long C0[2], C1[2], D0[2], D1[2], buffer[2];

  for (i = 1; i <= ROUNDS; i++) {
    i1 = i - 1;
    if (i == 1 || i == 2 || i == 9 || i == 16)
      v[i1] = 1;
    else v[i1] = 2;
  }
  C0[0] = C0[1] = D0[0] = D1[0] = 0;
  for (i = 1; i <= 28; i++) {
    i1 = i - 1;
    i3 = 32 - i;
    C0[0] |= get_bit(PC1_C[i1], key) << i3;
    D0[0] |= get_bit(PC1_D[i1], key) << i3;
  }
  for (i = 1; i <= ROUNDS; i++) {
    i1 = i - 1;
    C1[0] = left_shift_28(C0[0], v[i1]);
    D1[0] = left_shift_28(D0[0], v[i1]);
    C0[0] = C1[0];
    C0[1] = C1[1];
    D0[0] = D1[0];
    D0[1] = D1[1];
    buffer[0] = buffer[1] = 0;
    for (j = 1; j <= 28; j++) {
      set_bit(j, get_bit(j, C0), buffer);
      k = (char)(28 + j);
      set_bit(k, get_bit(j, D0), buffer);
    }
    K[i1][1] = 0;
    for (j = 1; j <= 48; j++)
      set_bit(j, get_bit(PC2[j - 1], buffer), K[i1]);
  }
}

void DES_reverse_key(long KE[ROUNDS][2], long KD[ROUNDS][2])
{
  int i, i15;

  for (i = 0; i < ROUNDS; i++) {
    i15 = 15 - i;
    KD[i15][0] = KE[i][0];
    KD[i15][1] = KE[i][1];
  }
}

void DES(long K[ROUNDS][2], long m[2], long c[2])
{
  int i, i1, j;
  long B[8], L0[2], R0[2], L1[2], R1[2];
  long T[2], Tp[2], Tpp[2], Tppp[2];
  long Bj, b1, b2, b3, b4, b5, b6, col, row;
  long t[8], tpp, buffer[2];

  for (i = 1; i <= 64; i++)
    set_bit(i, get_bit(IP[i - 1], m), buffer);
  L0[0] = buffer[0];
  R0[0] = buffer[1];
  L0[1] = R0[1] = 0;
  for (i = 1; i <= ROUNDS; i++) {
    L1[0] = R0[0];
    L1[1] = R0[1];
    for (j = 1; j <= 48; j++)
      set_bit(j, get_bit(E[j - 1], R0), T);
    i1 = i - 1;
    Tp[0] = T[0] ^ K[i1][0];
    Tp[1] = (T[1] ^ K[i1][1]) & 0xffff0000;
    B[0] = (Tp[0] >> 26) & 0x3f;
    B[1] = (Tp[0] >> 20) & 0x3f;
    B[2] = (Tp[0] >> 14) & 0x3f;
    B[3] = (Tp[0] >>  8) & 0x3f;
    B[4] = (Tp[0] >>  2) & 0x3f;
    B[5] = ((Tp[0] & 0x3) << 4) | ((Tp[1] >> 28) & 0xf);
    B[6] = (Tp[1] >> 22) & 0x3f;
    B[7] = (Tp[1] >> 16) & 0x3f;
    for (j = 0; j < 8; j++) {
      Bj = B[j];
      b1 = Bj >> 5;
      b2 = (Bj >> 4) & 1;
      b3 = (Bj >> 3) & 1;
      b4 = (Bj >> 2) & 1;
      b5 = (Bj >> 1) & 1;
      b6 = Bj & 1;
      row = 2 * b1 + b6;
      col = 8 * b2 + 4 * b3 + 2 * b4 + b5;
      t[j] = S[j][row][col];
    }
    tpp = (t[0] << 28) | (t[1] << 24)
        | (t[2] << 20) | (t[3] << 16)
        | (t[4] << 12) | (t[5] <<  8)
        | (t[6] <<  4) | t[7];
    Tpp[0] = tpp;
    Tpp[1] = 0;
    for (j = 1; j <= 32; j++)
      set_bit(j, get_bit(P[j - 1], Tpp), Tppp);
    R1[0] = L0[0] ^ Tppp[0];
    L0[0] = L1[0];
    R0[0] = R1[0];
    L1[1] = R1[1] = 0;
    #ifdef DEBUG
    printf("\ndata for round %d\n", i);
    printf("E(R%d) = ", i - 1);
    printf("%8x %8x\n", T[0], T[1]);
    printf("K%d = ", i);
    printf("%8x %8x\n", K[i1][0], K[i1][1]);
    printf("E(R%d) ^ K%d = ", i - 1, i);
    printf("%8x %8x\n", Tp[0], Tp[1]);
    printf("S box result = ");
    printf("%8x\n", tpp);
    printf("f(R%d, K%d) = ", i - 1, i);
    printf("%8x\n", Tppp[0]);
    printf("R%d = ", i);
    printf("%8x\n", R1[0]);
    #endif
  }
  for (i = 1; i <= 32; i++) {
    set_bit(i, get_bit(i, R1), buffer);
    j = 32 + i;
    set_bit(j, get_bit(i, L1), buffer);
  }
  for (i = 1; i <= 64; i++)
    set_bit(i, get_bit(IPI[i - 1], buffer), c);
}

void MMO_hash(char *buffer, long length, long *H0)
/* Matayas-Meyer-Oseas hash function */
{
  char *padded;
  long K[ROUNDS][2], c[2], i, m[2];
  long t = (length >> LOG_N_BYTES) + 1;

  /* use unambiguous padding 9.30 Algorithm Padding Method 2 */
  padded = calloc(t * BYTES_PER_BLOCK, sizeof(char));
  memcpy(padded, buffer, length);
  padded[length] = 0x80;
  for (i = 0; i < t; i++) {
    memcpy(m, padded + i * BYTES_PER_BLOCK, BYTES_PER_BLOCK);
    DES_key_schedule(K, H0);
    DES(K, m, c);
    H0[0] = m[0] ^ c[0];
    H0[1] = m[1] ^ c[1];
  }
  free(padded);
}

int main(void)
{
  char buffer[32] = "abcdefghijklmnopqrstuvwxyz";
  long H0[2], H0_bit[64], I0_bit[64], I0[2];
  long count = 0, i, length = 26;

  srand(time(NULL));
  H0[0] = I0[0] = (rand() << 16) | rand();
  H0[1] = I0[1] = (rand() << 16) | rand();
  printf("%s\n", buffer);
  printf("before H0 = %8x %8x\n", H0[0], H0[1]);
  MMO_hash(buffer, length, H0);
  printf("after  H0 = %8x %8x\n", H0[0], H0[1]);
  buffer[0] -= (char) 1;
  printf("%s\n", buffer);
  printf("before H0 = %8x %8x\n", I0[0], I0[1]);
  MMO_hash(buffer, length, I0);
  printf("after  H0 = %8x %8x\n", I0[0], I0[1]);
  for (i = 1; i <= 64; i++) {
    H0_bit[i] = get_bit(i, H0);
    I0_bit[i] = get_bit(i, I0);
    if (H0_bit[i] != I0_bit[i]) count++;
  }
  printf("a 1 bit change in input ");
  printf("causes %ld bits to change in output\n", count);
  return 0;
}
