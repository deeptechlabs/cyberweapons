/*
  Author:  Pate Williams (c) 1997

  ESIGN digital signature scheme. See "Handbook of
  Applied Cryptography" by Alfred J. Menezes et al
  Section 11.7.2 pages 473 - 474.
*/

#include <math.h>
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

void ESIGN_gen_keys(long length, long *k,
                    verylong *zn, verylong *zp,
                    verylong *zq)
/* generate public key (n, k) and private key (p, q) */
{
  verylong za = 0;

  zrstarts(time(NULL));
  zrandomprime(length, 5l, zp, zrandomb);
  zrandomprime(length, 5l, zq, zrandomb);
  zsq(*zp, &za);
  zmul(za, *zq, zn);
  do *k = rand() % 129l; while (*k < 4);
  zfree(&za);
}

void zhorner(ulong *digest, verylong *zs)
{
  long i;
  verylong za = 0, zb = 0, zx = 0;

  zintoz(2147483647l, &za);
  zlshift(za, 1l, &zb);
  zsadd(zb, 2l, &zx);
  if (digest[0] >= 2147483648ul) {
    zintoz((long)(digest[0] - 2147483648ul), &za);
    zsadd(za, 2147483647l, &zb);
    zsadd(zb, 1l, zs);
  }
  else zintoz(digest[0], zs);
  for (i = 1; i < 5; i++) {
    if (digest[i] >= 2147483648ul) {
      zintoz((long)(digest[i] - 2147483648ul), &za);
      zsadd(za, 2147483647l, &zb);
      zsadd(zb, 1l, &za);
    }
    else zintoz(digest[i], &za);
    zmul(*zs, zx, &zb);
    zadd(za, zb, zs);
  }
  zfree(&za);
  zfree(&zb);
  zfree(&zx);
}

void ESIGN_sign(uchar *m, ulong length, long k,
                verylong zn, verylong zp,
                verylong zq, verylong *zs)
{
  long k1 = k - 1;
  struct SHA_1_struct data;
  ulong blocks, digest[5], i, left;
  verylong za = 0, zb = 0, zc = 0, zv = 0;
  verylong zw = 0, zx = 0, zy = 0;
  verylong zpq = 0;

  SHA_1_init(length, &data);
  blocks = length / 64l;
  left = length % 64l;
  for (i = 0; i < blocks; i++)
    SHA_1_update(m + i * 64l, &data);
  SHA_1_final(m + blocks * 64l, left, digest, &data);
  zhorner(digest, &zv);
  zrandomb(zp, &zx);
  zsexp(zx, k, &za);
  zsubmod(zv, za, zn, &zb);
  zmul(zp, zq, &zpq);
  zdiv(zb, zpq, &za, &zb);
  zsadd(za, 1l, &zw);
  zsexp(zx, k1, &za);
  zsmul(za, k, &zb);
  zinvmod(zb, zp, &za);
  zmulmod(za, zw, zp, &zy);
  zmulmod(zy, zpq, zn, &za);
  zaddmod(za, zx, zn, zs);
  #ifdef DEBUG
  printf("%ul %s\n", length, m);
  for (i = 0; i < 5; i++)
    printf("%lx\n", digest[i]);
  printf("v = "); zwriteln(zv);
  printf("pq = "); zwriteln(zpq);
  printf("log2(pq) = %ld\n", z2log(zpq));
  #endif
  zfree(&za);
  zfree(&zb);
  zfree(&zc);
  zfree(&zv);
  zfree(&zw);
  zfree(&zx);
  zfree(&zy);
  zfree(&zpq);
}

int ESIGN_verify(uchar *m, ulong length, long k,
                 verylong zn, verylong zs)
{
  int value;
  long log;
  struct SHA_1_struct data;
  ulong blocks, digest[5], i, left;
  verylong za = 0, zb = 0, zk = 0, zu = 0, zz = 0;

  SHA_1_init(length, &data);
  blocks = length / 64l;
  left = length % 64l;
  for (i = 0; i < blocks; i++)
    SHA_1_update(m + i * 64l, &data);
  SHA_1_final(m + blocks * 64l, left, digest, &data);
  zhorner(digest, &zz);
  zintoz(k, &zk);
  zexpmod(zs, zk, zn, &zu);
  zone(&za);
  log = ceil((2.0 * z2log(zn)) / 3.0);
  zlshift(za, log, &zb);
  zadd(zz, zb, &za);
  #ifdef DEBUG
  printf("%ul %ld %s\n", length, log, m);
  for (i = 0; i < 5; i++)
    printf("%lx\n", digest[i]);
  printf("log2(n) = %ld\n", z2log(zn));
  printf("z = "); zwriteln(zz);
  printf("u = "); zwriteln(zu);
  printf("a = "); zwriteln(za);
  printf("compare(z, u) = %d\n", zcompare(zz, zu));
  printf("compare(u, a) = %d\n", zcompare(zu, za));
  #endif
  value = zcompare(zz, zu) <= 0 && zcompare(zu, za) <= 0;
  zfree(&za);
  zfree(&zb);
  zfree(&zk);
  zfree(&zu);
  zfree(&zz);
  return value;
}

int main(void)
{
  long k;
  uchar m[16] = "abc";
  verylong zn = 0, zp = 0, zq = 0, zs = 0;

  ESIGN_gen_keys(256l, &k, &zn, &zp, &zq);
  #ifdef DEBUG
  printf("%s\n", m);
  #endif
  ESIGN_sign(m, 3ul, k, zn, zp, zq, &zs);
  #ifdef DEBUG
  printf("k = %ld\n", k);
  printf("n = "); zwriteln(zn);
  printf("p = "); zwriteln(zp);
  printf("q = "); zwriteln(zq);
  printf("s = "); zwriteln(zs);
  printf("%s\n", m);
  #endif
  printf("%d\n", ESIGN_verify(m, 3ul, k, zn, zs));
  zfree(&zn);
  zfree(&zp);
  zfree(&zq);
  zfree(&zs);
  return 0;
}
