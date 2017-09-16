/*
  Author:  Pate Williams (c) 1997

  Guillou-Quisquater signature scheme. See "Handbook
  of Applied Cryptography" by Alfred J. Menezes et al
  pages 450 - 451. Also see Section 14.5.2 page 612.
*/

#include <malloc.h>
#include <mem.h>
#include <stdio.h>
#include <time.h>
#include "lip.h"

#define CRT_SIZE 128l
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

void Garner(long t, verylong *zm, verylong *zv, verylong *zx)
/* solution of the Chinese remaider theorem */
{
  long i, j;
  verylong za = 0, zb = 0, zu = 0, zC[CRT_SIZE];

  for (i = 0; i < CRT_SIZE; i++) zC[i] = 0;
  for (i = 1; i < t; i++) {
    zone(&zC[i]);
    for (j = 0; j <= i - 1; j++) {
      zinvmod(zm[j], zm[i], &zu);
      zmulmod(zu, zC[i], zm[i], &za);
      zcopy(za, &zC[i]);
    }
  }
  zcopy(zv[0], &zu);
  zcopy(zu, zx);
  for (i = 1; i < t; i++) {
    zsub(zv[i], *zx, &za);
    zmulmod(za, zC[i], zm[i], &zu);
    zone(&za);
    for (j = 0; j <= i - 1; j++) {
      zmul(za, zm[j], &zb);
      zcopy(zb, &za);
    }
    zmul(za, zu, &zb);
    zadd(*zx, zb, &za);
    zcopy(za, zx);
  }
  zfree(&za);
  zfree(&zb);
  zfree(&zu);
  for (i = 0; i < CRT_SIZE; i++) zfree(&zC[i]);
}

void GQ_gen_keys(long length, verylong *zJA, verylong *za,
                 verylong *ze, verylong *zn)
{
  verylong zd = 0, zd1 = 0, zd2 = 0, ze1 = 0;
  verylong zn1 = 0, zp = 0, zp1 = 0, zq = 0, zq1 = 0;
  verylong zJA1 = 0, zm[2], zv[2];

  zm[0] = zm[1] = zv[0] = zv[1] = 0;
  zrstarts(time(NULL));
  zrandomprime(length, 5l, &zp, zrandomb);
  zrandomprime(length, 5l, &zq, zrandomb);
  zmul(zp, zq, zn);
  zsadd(zp, - 1l, &zp1);
  zsadd(zq, - 1l, &zq1);
  zmul(zp1, zq1, &zn1);
  do {
    do
      zrandomb(*zn, ze);
     while (zscompare(*ze, 0l) == 0);
    zgcd(*ze, zn1, &zd);
  } while (zscompare(zd, 1l) != 0);
  do {
    do
      zrandomb(*zn, zJA);
    while (zscompare(*zJA, 1l) <= 0);
    zgcd(*zJA, *zn, &zd);
  } while (zscompare(zd, 1l) != 0);
  zinvmod(*zJA, *zn, &zJA1);
  zinvmod(*ze, zp1, &zd1);
  zinvmod(*ze, zq1, &zd2);
  zexpmod(zJA1, zd1, zp, &zv[0]);
  zexpmod(zJA1, zd2, zq, &zv[1]);
  zcopy(zp, &zm[0]);
  zcopy(zq, &zm[1]);
  Garner(2l, zm, zv, za);
  /* check our work */
  zexpmod(*za, *ze, *zn, &zd);
  zmulmod(zd, *zJA, *zn, &zp);
  if (zscompare(zp, 1l) != 0)
    printf("JA * a ^ e != 1 mod n");
  #ifdef DEBUG
  printf("JA = "); zwriteln(*zJA);
  #endif
  zfree(&zd);
  zfree(&zd1);
  zfree(&zd2);
  zfree(&ze1);
  zfree(&zn1);
  zfree(&zp);
  zfree(&zp1);
  zfree(&zq);
  zfree(&zq1);
  zfree(&zJA1);
  zfree(&zm[0]);
  zfree(&zm[1]);
  zfree(&zv[0]);
  zfree(&zv[1]);
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

void GQ_sign(uchar *buffer, ulong length,
             verylong za, verylong ze, verylong zn,
             verylong *zl, verylong *zs)
{
  long log;
  struct SHA_1_struct data;
  uchar *m;
  ulong blocks, digest[5], i, j, left, len;
  verylong zb = 0, zk = 0, zr = 0, zt = 0;

  do
    zrandomb(zn, &zk);
  while (zscompare(zk, 1l) <= 0);
  zexpmod(zk, ze, zn, &zr);
  zcopy(zr, &zt);
  log = z2log(zr);
  len = length + log / 8l;
  if (log % 8l != 0) len++;
  m = malloc(len * sizeof(uchar));
  memcpy(m, buffer, length);
  i = length;
  for (j = 0; j < log / 8l; j++) {
    zlowbits(zt, 8l, &zb);
    m[i++] = (uchar) (zb[1] & 255);
    zrshift(zt, 1l, &zb);
    zcopy(zb, &zt);
  }
  if (log % 8l != 0) m[i] = (uchar) (zr[1] & 255);
  SHA_1_init(len, &data);
  blocks = len / 64l;
  left = blocks % 64l;
  for (i = 0; i < blocks; i++)
    SHA_1_update(m + i * 64l, &data);
  SHA_1_final(m + blocks * 64l, left, digest, &data);
  zhorner(digest, zl);
  zexpmod(za, *zl, zn, &zb);
  zmulmod(zk, zb, zn, zs);
  #ifdef DEBUG
  printf("%s\n", buffer);
  printf("e = "); zwriteln(ze);
  printf("l = "); zwriteln(*zl);
  printf("n = "); zwriteln(zn);
  printf("s = "); zwriteln(*zs);
  printf("r = "); zwriteln(zr);
  #endif
  free(m);
  zfree(&zb);
  zfree(&zk);
  zfree(&zr);
  zfree(&zt);
}

int GQ_verify(uchar *buffer, ulong length,
              verylong zJA, verylong ze, verylong zl,
              verylong zn, verylong zs)
{
  int value;
  long log;
  struct SHA_1_struct data;
  uchar *m;
  ulong blocks, digest[5], i, j, left, len;
  verylong za = 0, zb = 0, zlp = 0, zu = 0;

  zexpmod(zs, ze, zn, &za);
  zexpmod(zJA, zl, zn, &zb);
  zmulmod(za, zb, zn, &zu);
  #ifdef DEBUG
  printf("JA = "); zwriteln(zJA);
  printf("%s\n", buffer);
  printf("e = "); zwriteln(ze);
  printf("l = "); zwriteln(zl);
  printf("n = "); zwriteln(zn);
  printf("s = "); zwriteln(zs);
  printf("u = "); zwriteln(zu);
  #endif
  log = z2log(zu);
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
  zhorner(digest, &zlp);
  #ifdef DEBUG
  printf("l' = "); zwriteln(zlp);
  #endif
  value = zcompare(zl, zlp) == 0;
  free(m);
  zfree(&za);
  zfree(&zb);
  zfree(&zlp);
  zfree(&zu);
  return value;
}

int main(void)
{
  long i, t = 4l;
  uchar buffer[16] = "abcd";
  verylong zJA = 0, za = 0, ze = 0, zl = 0;
  verylong zn = 0, zs = 0, zx = 0, zm[4], zv[4];

  for (i = 0; i < 4; i++) zm[i] = zv[i] = 0;
  zintoz(5, &zm[0]);
  zintoz(7, &zm[1]);
  zintoz(11, &zm[2]);
  zintoz(13, &zm[3]);
  zintoz(2, &zv[0]);
  zintoz(1, &zv[1]);
  zintoz(3, &zv[2]);
  zintoz(8, &zv[3]);
  Garner(t, zm, zv, &zx);
  if (zscompare(zx, 2192l) != 0)
    printf("error in Garner!\n");
  GQ_gen_keys(256l, &zJA, &za, &ze, &zn);
  GQ_sign(buffer, 4ul, za, ze, zn, &zl, &zs);
  printf("%d\n", GQ_verify(buffer, 4ul, zJA, ze, zl, zn, zs));
  zfree(&zJA);
  zfree(&za);
  zfree(&ze);
  zfree(&zl);
  zfree(&zn);
  zfree(&zs);
  zfree(&zx);
  for (i = 0; i < 4; i++) {
    zfree(&zm[i]);
    zfree(&zv[i]);
  }
  return 0;
}
