/*
  Author:  Pate Williams (c) 1997

  Secure hash algorithm updated version.
  See "Handbook of Applied Cryptography"
  by Alfred J. Menezes et al editors,
  9.53 Algorithm page 348.
*/

#include <mem.h>
#include <stdio.h>
#include <string.h>

#define LITTLE_ENDIAN

typedef unsigned char uchar;
typedef unsigned long ulong;

struct SHA_1_struct {
  ulong A, B, C, D, E, H1, H2, H3, H4, H5;
  struct {ulong hi, lo;} length;
};

union ByteWord {
  uchar byte[4];
  ulong word;
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

#ifdef LITTLE_ENDIAN

void BigEndian(int number, ulong *buffer)
{
  int i;
  union ByteWord byteWord;
  uchar *cp = (uchar *) buffer;

  for (i = 0; i < (number >> 2); i++) {
    byteWord.byte[0] = *(cp + 3);
    byteWord.byte[1] = *(cp + 2);
    byteWord.byte[2] = *(cp + 1);
    byteWord.byte[3] = *cp;
    buffer[i] = byteWord.word;
    cp += 4;
  }
}

#endif

ulong LeftShift(ulong x, int number)
/* left circular shift number bits */
{
  return (x << number) | (x >> (32 - number));
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

void SHA_1_init(ulong number, struct SHA_1_struct *data)
{
  static ulong h1 = 0x67452301ul, h2 = 0xefcdab89ul,
               h3 = 0x98badcfeul, h4 = 0x10325476ul,
               h5 = 0xc3d2e1f0ul;

  data->H1 = h1, data->H2 = h2, data->H3 = h3;
  data->H4 = h4, data->H5 = h5;
  /* determine bit length of the message */
  data->length.hi = number >> 29;
  data->length.lo = number << 3;
}

void SHA_1_update(uchar *buffer, struct SHA_1_struct *data)
{
  int j;
  static ulong y1 = 0x5a827999ul, y2 = 0x6ed9eba1ul,
               y3 = 0x8f1bbcdcul, y4 = 0xca62c1d6ul;
  ulong M[16], X[80];

  memcpy((uchar *) M, buffer, 64);
  #ifdef LITTLE_ENDIAN
  BigEndian(64, M);
  #endif
  memcpy(X, M, sizeof(M));
  data->A = data->H1;
  data->B = data->H2;
  data->C = data->H3;
  data->D = data->H4;
  data->E = data->H5;
  for (j = 16; j < 80; j++)
    X[j] = LeftShift(X[j - 3] ^ X[j - 8] ^ X[j - 14] ^ X[j - 16], 1);
  Round( 0, y1, X, data, f);
  Round(20, y2, X, data, h);
  Round(40, y3, X, data, g);
  Round(60, y4, X, data, h);
  data->H1 += data->A;
  data->H2 += data->B;
  data->H3 += data->C;
  data->H4 += data->D;
  data->H5 += data->E;
}

void SHA_1_final(uchar *buffer, ulong number, ulong *digest,
                 struct SHA_1_struct *data)
{
  uchar *cp;
  ulong M[16];

  number %= 64;
  memcpy((uchar *) M, buffer, number);
  cp = (uchar *) M + number;
  *cp = 0x80;
  number++;
  memset((uchar *) M + number, 0, 56 - number);
  memcpy((uchar *) M + 56, &data->length, 8);
  #ifdef LITTLE_ENDIAN
  BigEndian(8, M + 14);
  #endif
  SHA_1_update((uchar *) M, data);
  memcpy(digest, &data->H1, 20);
  memset(data, 0, sizeof(struct SHA_1_struct));
}

void do_buffer(uchar *buffer)
{
  ulong digest[5], i, length;
  struct SHA_1_struct data;

  length = strlen((char *) buffer);
  SHA_1_init(length, &data);
  SHA_1_final(buffer, length, digest, &data);
  printf("%s\n", buffer);
  for (i = 0; i < 5; i++)
    printf("%lx ", digest[i]);
  printf("\n");
}

int main(void)
{
  uchar buffer1[32] = "";
  uchar buffer2[32] = "a";
  uchar buffer3[32] = "abc";
  uchar buffer4[32] = "abcdefghijklmnopqrstuvwxyz";

  do_buffer(buffer1);
  do_buffer(buffer2);
  do_buffer(buffer3);
  do_buffer(buffer4);
  return 0;
}
