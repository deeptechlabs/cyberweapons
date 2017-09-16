/*
  Author:  Pate Williams (c) 1997

  Feige-Fiat-Shamir signature scheme. See "Handbook
  of Applied Cryptography" by Alfred J. Menezes et
  al section 11.4 pages 447 - 448.
*/

#include <mem.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "lip.h"

#define DEBUG
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
//left circular shift number bits
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

void FFS_gen_keys(long k, long length, verylong *zn,
                  verylong *zs, verylong *zv)
/* k should be greater than 160 bits and length is
   the desired bit length of p and q
   the public key zv should be an array of k elements
   the private key zs should be an array of k elements */
{
  int found;
  long i, j;
  verylong za = 0, zb = 0, zp = 0, zq = 0;

  zrstarts(time(NULL));
  zrandomprime(length, 5l, &zp, zrandomb);
  zrandomprime(length, 5l, &zq, zrandomb);
  zmul(zp, zq, zn);
  for (i = 0; i < k; i++) {
    do {
      do zrandomb(*zn, &za); while (zscompare(za, 0l) == 0);
      found = 0;
      for (j = 0; j < k && !found; j++)
        found = zcompare(za, zs[j]) == 0;
    } while (found);
    zcopy(za, &zs[i]);
    zinvmod(za, *zn, &zb);
    zmulmod(zb, zb, *zn, &zv[i]);
  }
  zfree(&za);
  zfree(&zb);
  zfree(&zp);
  zfree(&zq);
}

void FFS_sign(uchar *buffer, ulong k, ulong length, long *e,
              verylong zn, verylong *zs,
              verylong *zt)
{
  long log;
  uchar *m;
  ulong blocks, d, i, j, l, len, left, digest[5];
  struct SHA_1_struct data;
  verylong za = 0, zb = 0, zr = 0, zu = 0;

  do zrandomb(zn, &zr); while (zscompare(zr, 0l) == 0);
  zmulmod(zr, zr, zn, &zu);
  log = z2log(zu);
  #ifdef DEBUG
    printf("%ld ", k);
    zwriteln(zu);
  #endif
  len = length + log / 8l;
  if (log % 8l != 0) len++;
  m = malloc(len * sizeof(uchar));
  memcpy(m, buffer, length);
  i = length;
  for (j = 0; j < log / 8l; j++) {
    zlowbits(zu, 8l, &za);
    m[i++] = (uchar) (za[1] & 255);
    zrshift(zu, 1l, &za);
    zcopy(za, &zu);
  }
  if (log % 8l != 0) m[i] = (uchar) (zu[1] & 255);
  SHA_1_init(len, &data);
  blocks = len / 64l;
  left = blocks % 64l;
  for (i = 0; i < blocks; i++)
    SHA_1_update(m + i * 64l, &data);
  SHA_1_final(m + blocks * 64l, left, digest, &data);
  i = 0;
  for (j = 0; j < 5; j++) {
    d = digest[j];
    for (l = 0; l < 32; l++) {
      e[i++] = d & 1;
      d >>= 1;
    }
  }
  zone(&za);
  for (j = 0; j < k; j++) {
    if (e[j] != 0) {
      zmulmod(zs[j], za, zn, &zb);
      zcopy(zb, &za);
    }
  }
  zmulmod(za, zr, zn, zt);
  zfree(&za);
  zfree(&zb);
  zfree(&zr);
  zfree(&zu);
}

int FFS_verify(uchar *buffer, ulong k, ulong length,
               long *e, verylong zn, verylong zs,
               verylong *zv)
/* returns 0 if the signature is rejected 1 if accepeted */
{
  int value;
  long ep[8192], log;
  uchar *m;
  ulong blocks, d, i, j, l, len, left, digest[5];
  struct SHA_1_struct data;
  verylong za = 0, zb = 0, zw = 0;

  zone(&za);
  for (j = 0; j < k; j++) {
    if (e[j] != 0) {
      zmulmod(zv[j], za, zn, &zb);
      zcopy(zb, &za);
    }
  }
  zmulmod(zs, za, zn, &zb);
  zmulmod(zs, zb, zn, &zw);
  log = z2log(zw);
  #ifdef DEBUG
    printf("%ld ", k);
    zwriteln(zw);
  #endif
  len = length + log / 8l;
  if (log % 8l != 0) len++;
  m = malloc(len * sizeof(uchar));
  memcpy(m, buffer, length);
  i = length;
  for (j = 0; j < log / 8l; j++) {
    zlowbits(zw, 8l, &za);
    m[i++] = (uchar) (za[1] & 255);
    zrshift(zw, 1l, &za);
    zcopy(za, &zw);
  }
  if (log % 8l != 0) m[i] = (uchar) (zw[1] & 255);
  SHA_1_init(len, &data);
  blocks = len / 64l;
  left = blocks % 64l;
  for (i = 0; i < blocks; i++)
    SHA_1_update(m + i * 64l, &data);
  SHA_1_final(m + blocks * 64l, left, digest, &data);
  i = 0;
  for (j = 0; j < 5; j++) {
    d = digest[j];
    for (l = 0; l < 32; l++) {
      ep[i++] = d & 1;
      d >>= 1;
    }
  }
  value = 1;
  for (i = 0; i < k && value; i++)
    value = ep[i] == e[i];
  zfree(&za);
  zfree(&zb);
  zfree(&zw);
  return value;
}

int main(void)
{
  long e[8192];
  uchar buffer[64] = "abcd";
  ulong i, k = 160;
  verylong zn = 0, zt = 0, zs[8192], zv[8192];

  for (i = 0; i < 8192; i++) zs[i] = zv[i] = 0;
  FFS_gen_keys(k, 200ul, &zn, zs, zv);
  FFS_sign(buffer, k, 4ul, e, zn, zs, &zt);
  printf("%d\n", FFS_verify(buffer, k, 4ul, e, zn, zt, zv));
  zfree(&zn);
  zfree(&zt);
  for (i = 0; i < 8192; i++) {
    zfree(&zs[i]);
    zfree(&zv[i]);
  }
  return 0;
}
