/*
  Author:  Pate Williams (c) 1997

  SAFER K-64 (Secure and Fast Encryption Routine).
  See "Handbook of Applied Cryptography" by Alfred
  J. Menezes et al 7.7.1 Section pages 266 - 269.
*/

#include <stdio.h>
#include <stdlib.h>

/* define the constant number of rounds */

#define ROUNDS 6
#define DEBUG

typedef unsigned char uchar;

void generate_S_boxes(short *S, short *S_inv)
{
  short g = 45, i, j, t;

  S[0] = 1, S_inv[1] = 0;
  for (i = 1; i <= 255; i++) {
    t = (short) ((g * S[i - 1]) % 257);
    S[i] = t;
    S_inv[t] = (uchar) i;
  }
  S[128] = 0, S_inv[0] = 128;
  #ifdef DEBUG
  for (i = 0; i < 16; i++) {
    for (j = 0; j < 16; j++)
      printf("%3d ", S[i * 16 + j]);
    printf("\n");
  }
  #endif
}

void SAFER_K_64_key_schedule(short *key, short *S,
                             short *S_inv, uchar **K)
{
  uchar B[2 * ROUNDS + 3][9], R[9], i, i2, j, t;

  generate_S_boxes(S, S_inv);
  for (i = 2; i <= 2 * ROUNDS + 1; i++)
    for (j = 1; j <= 8; j++)
      B[i][j] = (uchar) S[S[9 * i + j]];
  for (i = 0; i < 4; i++) {
    i2= (uchar) (2 * i);
    R[i2 + 1] = (uchar) (key[i] >> 8);
    R[i2 + 2] = (uchar) (key[i] & 255);
  }
  #ifdef DEBUG
  for (i = 1; i <= 8; i++)
    printf("%3d ", B[2][i]);
  printf("\n");
  for (i = 1; i <= 8; i++)
    printf("%3d ", B[13][i]);
  printf("\n");
  for (i = 1; i <= 8; i++)
    printf("%3d ", R[i]);
  printf("\n");
  #endif
  for (i = 1; i <= 8; i++) K[1][i] = R[i];
  for (i = 2; i <= 2 * ROUNDS + 1; i++) {
    for (j = 1; j <= 8; j ++) {
      t = R[j];
      R[j] = (uchar) ((t << 3) | (t >> 5));
    }
    for (j = 1; j <= 8; j++)
      K[i][j] = (uchar) ((R[j] + B[i][j]) % 256);
  }
}

void f(uchar x, uchar y, uchar *X, uchar *Y)
{
  int a = (2 * x + y) % 256;
  int b = (x + y) % 256;

  *X = (uchar) a, *Y = (uchar) b;
}

void SAFER_K_64_encryption(uchar *X, uchar *Y,
                           short *S, short *S_inv,
                           uchar **K)
{
  uchar i, j;

  for (i = 1; i <= ROUNDS; i++) {
    j = (uchar) (2 * i - 1);
    X[1] ^= K[j][1];
    X[4] ^= K[j][4];
    X[5] ^= K[j][5];
    X[8] ^= K[j][8];
    X[2] = (uchar) ((X[2] + K[j][2]) % 256);
    X[3] = (uchar) ((X[3] + K[j][3]) % 256);
    X[6] = (uchar) ((X[6] + K[j][6]) % 256);
    X[7] = (uchar) ((X[7] + K[j][7]) % 256);
    X[1] = S[X[1]];
    X[4] = S[X[4]];
    X[5] = S[X[5]];
    X[8] = S[X[8]];
    X[2] = S_inv[X[2]];
    X[3] = S_inv[X[3]];
    X[6] = S_inv[X[6]];
    X[7] = S_inv[X[7]];
    j = (uchar) (2 * i);
    X[1] = (uchar) ((X[1] + K[j][1]) % 256);
    X[4] = (uchar) ((X[4] + K[j][4]) % 256);
    X[5] = (uchar) ((X[5] + K[j][5]) % 256);
    X[8] = (uchar) ((X[8] + K[j][8]) % 256);
    X[2] ^= K[j][2];
    X[3] ^= K[j][3];
    X[6] ^= K[j][6];
    X[7] ^= K[j][7];
    f(X[1], X[2], &X[1], &X[2]);
    f(X[3], X[4], &X[3], &X[4]);
    f(X[5], X[6], &X[5], &X[6]);
    f(X[7], X[8], &X[7], &X[8]);
    f(X[1], X[3], &Y[1], &Y[2]);
    f(X[5], X[7], &Y[3], &Y[4]);
    f(X[2], X[4], &Y[5], &Y[6]);
    f(X[6], X[8], &Y[7], &Y[8]);
    for (j = 1; j <= 8; j++) X[j] = Y[j];
    f(X[1], X[3], &Y[1], &Y[2]);
    f(X[5], X[7], &Y[3], &Y[4]);
    f(X[2], X[4], &Y[5], &Y[6]);
    f(X[6], X[8], &Y[7], &Y[8]);
    for (j = 1; j <= 8; j++) X[j] = Y[j];
  }
  i = 2 * ROUNDS + 1;
  Y[1] = X[1] ^ K[i][1];
  Y[4] = X[4] ^ K[i][4];
  Y[5] = X[5] ^ K[i][5];
  Y[8] = X[8] ^ K[i][8];
  Y[2] = (uchar) ((X[2] + K[i][2]) % 256);
  Y[3] = (uchar) ((X[3] + K[i][3]) % 256);
  Y[6] = (uchar) ((X[6] + K[i][6]) % 256);
  Y[7] = (uchar) ((X[7] + K[i][7]) % 256);
}

void f_inv(uchar L, uchar R, uchar *l, uchar *r)
{
  int a = (L - R) % 256;
  int b = (2 * R - L) % 256;

  *l = (uchar) a, *r = (uchar) b;
}

void SAFER_K_64_decryption(uchar *X, uchar *Y,
                           short *S, short *S_inv,
                           uchar **K)
{
  uchar i, j;

  i = 2 * ROUNDS + 1;
  Y[1] = X[1] ^ K[i][1];
  Y[4] = X[4] ^ K[i][4];
  Y[5] = X[5] ^ K[i][5];
  Y[8] = X[8] ^ K[i][8];
  Y[2] = (uchar) ((X[2] - K[i][2]) % 256);
  Y[3] = (uchar) ((X[3] - K[i][3]) % 256);
  Y[6] = (uchar) ((X[6] - K[i][6]) % 256);
  Y[7] = (uchar) ((X[7] - K[i][7]) % 256);
  for (i = 1; i <= 8; i++) X[i] = Y[i];
  for (i = ROUNDS; i >= 1; i--) {
    f_inv(X[1], X[2], &X[1], &X[2]);
    f_inv(X[3], X[4], &X[3], &X[4]);
    f_inv(X[5], X[6], &X[5], &X[6]);
    f_inv(X[7], X[8], &X[7], &X[8]);
    f_inv(X[1], X[5], &Y[1], &Y[2]);
    f_inv(X[2], X[6], &Y[3], &Y[4]);
    f_inv(X[3], X[7], &Y[5], &Y[6]);
    f_inv(X[4], X[8], &Y[7], &Y[8]);
    for (j = 1; j <= 8; j++) X[j] = Y[j];
    f_inv(X[1], X[5], &Y[1], &Y[2]);
    f_inv(X[2], X[6], &Y[3], &Y[4]);
    f_inv(X[3], X[7], &Y[5], &Y[6]);
    f_inv(X[4], X[8], &Y[7], &Y[8]);
    for (j = 1; j <= 8; j++) X[j] = Y[j];
    j = (uchar) (2 * i);
    X[1] = (uchar) ((X[1] - K[j][1]) % 256);
    X[4] = (uchar) ((X[4] - K[j][4]) % 256);
    X[5] = (uchar) ((X[5] - K[j][5]) % 256);
    X[8] = (uchar) ((X[8] - K[j][8]) % 256);
    X[2] ^= K[j][2];
    X[3] ^= K[j][3];
    X[6] ^= K[j][6];
    X[7] ^= K[j][7];
    X[1] = S_inv[X[1]];
    X[4] = S_inv[X[4]];
    X[5] = S_inv[X[5]];
    X[8] = S_inv[X[8]];
    X[2] = S[X[2]];
    X[3] = S[X[3]];
    X[6] = S[X[6]];
    X[7] = S[X[7]];
    j = (uchar) (2 * i - 1);
    X[1] ^= K[j][1];
    X[4] ^= K[j][4];
    X[5] ^= K[j][5];
    X[8] ^= K[j][8];
    X[2] = (uchar) ((X[2] - K[j][2]) % 256);
    X[3] = (uchar) ((X[3] - K[j][3]) % 256);
    X[6] = (uchar) ((X[6] - K[j][6]) % 256);
    X[7] = (uchar) ((X[7] - K[j][7]) % 256);
  }
  for (i = 1; i <= 8; i++) Y[i] = X[i];
}

void main(void)
{
  short key[4], S[512], S_inv[512];
  uchar X[9] = {0, 1, 2, 3, 4, 5, 6, 7, 8}, Y[9];
  uchar i, **K;

  K = calloc(2 * ROUNDS + 3, sizeof(char *));
  for (i = 0; i < 2 * ROUNDS + 3; i++)
    K[i] = calloc(9, sizeof(char));
  key[0] = 256 * 8 + 7;
  key[1] = 256 * 6 + 5;
  key[2] = 256 * 4 + 3;
  key[3] = 256 * 2 + 1;
  SAFER_K_64_key_schedule(key, S, S_inv, K);
  SAFER_K_64_encryption(X, Y, S, S_inv, K);
  printf("encryption results\n");
  for (i = 1; i <= 8; i++)
    printf("%3d ", Y[i]);
  printf("\n");
  SAFER_K_64_decryption(Y, X, S, S_inv, K);
  printf("decryption results\n");
  for (i = 1; i <= 8; i++)
    printf("%3d ", X[i]);
  printf("\n");
  for (i = 0; i < 2 * ROUNDS + 3; i++)
    free(K[i]);
  free(K);
}