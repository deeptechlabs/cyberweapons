/*
  Author:  Pate Williams (c) 1997

  RC5 encryption algorithm. See "Handbook of
  Applied Cryptography" 7.7.2 Section pages
  269 - 270.
*/

#include <stdio.h>
#include <stdlib.h>

#define KEY_BYTES 16
#define ROUNDS 12
#define WORD_LENGTH 32
#define Pw 0xb7e15163ul
#define Qw 0x9e3779b9ul

typedef unsigned char uchar;
typedef unsigned long ulong;

ulong RC5_rotate_left(ulong a, ulong c)
{
  return (a << c) | (a >> (32 - c));
}

void RC5_encryption(ulong A, ulong B, ulong *C, ulong *D,
                    ulong *K)
{
  int i, i2;

  A += K[0];
  B += K[1];
  for (i = 1; i <= ROUNDS; i++) {
    i2 = i * 2;
    A = RC5_rotate_left(A ^ B, B & 31) + K[i2];
    B = RC5_rotate_left(B ^ A, A & 31) + K[i2 + 1];
  }
  *C = A, *D = B;
}

ulong RC5_rotate_right(ulong a, ulong c)
{
  return (a >> c) | (a << (32 - c));
}

void RC5_decryption(ulong A, ulong B, ulong *C, ulong *D,
                    ulong *K)
{
  int i, i2;

  for (i = ROUNDS; i >= 1; i--) {
    i2 = i * 2;
    B = RC5_rotate_right(B - K[i2 + 1], A & 31) ^ A;
    A = RC5_rotate_right(A - K[i2], B & 31) ^ B;
  }
  *C = A - K[0], *D = B - K[1];
}

void RC5_key_schedule(uchar *key, ulong *K)
{
  int i, iu, u = WORD_LENGTH / 8, m;
  int j, c = KEY_BYTES / u, s, t;
  union {uchar byte[4]; ulong word;} byte_word;
  ulong A, B, *L;

  L = calloc(c, sizeof(ulong));
  for (i = KEY_BYTES; i <= c * u - 1; i++) key[i] = 0;
  for (i = 0; i < c; i++) {
    iu = i * u;
    for (j = 0; j < u; j++)
      byte_word.byte[j] = key[iu + j];
    L[i] = byte_word.word;
  }
  K[0] = Pw;
  for (i = 1; i <= 2 * ROUNDS + 1; i++)
    K[i] = K[i - 1] + Qw;
  i = j = 0, A = B = 0, m = 2 * ROUNDS + 2, t = max(c, m);
  for (s = 1; s <= 3 * t; s++) {
    K[i] = RC5_rotate_left(K[i] + A + B, 3);
    A = K[i];
    i = (i + 1) % m;
    L[j] = RC5_rotate_left(L[j] + A + B, (A + B) & 31);
    B = L[j];
    j = (j + 1) % c;
  }
  free(L);
}

int main(void)
{
  uchar key[KEY_BYTES] = {0x52, 0x69, 0xf1, 0x49,
                          0xd4, 0x1b, 0xa0, 0x15,
                          0x24, 0x97, 0x57, 0x4d,
                          0x7f, 0x15, 0x31, 0x25};
  ulong A = 0xb278c165ul, B = 0xcc97d184ul, C, D, E, F;
  ulong K[2 * ROUNDS + 2];

  RC5_key_schedule(key, K);
  RC5_encryption(A, B, &C, &D, K);
  printf("%8x %8x\n", C, D);
  RC5_decryption(C, D, &E, &F, K);
  printf("%8x %8x\n", E, F);
  return 0;
}
