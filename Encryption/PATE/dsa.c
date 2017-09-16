/*
  Author:  Pate Williams (c) 1997

  Digital Signature Algorithm (DSA).
  See "Handbook of Applied Cryptography"
  by Alfred J. Menezes et al editors
  pages 452-453.
*/

#include <malloc.h>
#include <mem.h>
#include <stdio.h>
#include <time.h>
#include "lip.h"

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

void gen_primes(long l, verylong *zp, verylong *zq)
{
  int flag = 0;
  long L = 512 + 64 * l, L1 = L - 1, b, i, j, k, m, length1, length2, n, n1;
  uchar m1[1024], m2[1024];
  ulong digest1[5], digest2[5];
  struct SHA_1_struct data1, data2;
  verylong zL = 0, zU = 0, zW = 0, zX = 0, zb = 0;
  verylong zc = 0, zg = 0, zs = 0, zt = 0, zu = 0;
  verylong zq2 = 0;
  verylong *za, *zV;

  zrstarts(time(NULL));
  b = L1 % 160l;
  n = L1 / 160l;
  n1 = n + 1;
  zV = calloc(n1, sizeof(verylong));
  za = calloc(n1, sizeof(verylong));
  zone(&zt);
  zlshift(zt, L1, &zL);
  zlshift(zt, b, &zb);
  for (i = 0; i < n1; i++)
    zlshift(zt, 160 * i, &za[i]);
  zlshift(zt, 160l, &zg);
  while (!flag) {
    do {
      zrandomprime(160l, 5l, &zs, zrandomb);
      zsadd(zs, 1l, &zt);
      length1 = 4l * zs[0];
      memcpy(m1, &zs[1], length1);
      length2 = 4l * zt[0];
      memcpy(m2, &zt[1], length2);
      SHA_1_init(length1, &data1);
      SHA_1_final(m1, length1, digest1, &data1);
      SHA_1_init(length2, &data2);
      SHA_1_final(m2, length2, digest2, &data2);
      zhorner(digest1, &zt);
      zmod(zt, zg, &zU);
      zcopy(zU, &zt);
      zor(zt, zg, &zU);
      zsadd(zU, 1l, zq);
    } while (!zprobprime(*zq, 18l));
    zsmul(*zq, 2l, &zq2);
    i = 0, j = 2;
    while (!flag && i < 4096) {
      for (k = 0; k < n; k++) {
        zsadd(zs, j + k, &zt);
        length1 = 4l * zt[0];
        memcpy(m1, &zt[1], length1);
        SHA_1_init(length1, &data1);
        SHA_1_final(m1, length1, digest1, &data1);
        zone(&zt);
        for (m = 0; m < 5; m++) {
          zsmul(zt, digest1[m], &zV[k]);
          zcopy(zV[k], &zt);
        }
      }
      zzero(&zW);
      for (m = 0; m < n; m++) {
        zmul(za[m], zV[m], &zt);
        zcopy(zW, &zu);
        zadd(zu, zt, &zW);
      }
      zmod(zV[n], zb, &zt);
      zmul(zt, za[n], &zu);
      zcopy(zW, &zt);
      zadd(zt, zu, &zW);
      zadd(zW, zL, &zX);
      zmod(zX, zq2, &zc);
      zsub(zX, zc, &zt);
      zsadd(zt, 1l, zp);
      if (zcompare(*zp, zL) >= 0 && zprobprime(*zp, 5)) {
        for (m = 0; m < n1; m++) {
          zfree(&zV[m]);
          zfree(&za[m]);
        }
        flag = 1;
      }
      i++, j = j + n + 1;
    }
  }
  zfree(&zL);
  zfree(&zU);
  zfree(&zW);
  zfree(&zX);
  zfree(&zb);
  zfree(&zc);
  zfree(&zg);
  zfree(&zs);
  zfree(&zt);
  zfree(&zu);
  zfree(&zq2);
}

void DSA_gen_keys(long t, verylong *za, verylong *zalpha,
                  verylong *zp, verylong *zq, verylong *zy)
{
  verylong ze = 0, zg = 0, zt = 0;

  gen_primes(t, zp, zq);
  zsadd(*zp, - 1l, &zt);
  zdiv(zt, *zq, &ze, &zg);
  do {
    do zrandomb(*zp, &zg); while (zscompare(zg, 1l) <= 0);
    zexpmod(zg, ze, *zp, zalpha);
  } while (zscompare(*zalpha, 1l) == 0);
  zsadd(*zq, - 1l, &zt);
  do zrandomb(zt, za); while (zscompare(*za, 0l) == 0);
  zexpmod(*zalpha, *za, *zp, zy);
  zfree(&ze);
  zfree(&zg);
  zfree(&zt);
}

void DSA_sign(uchar *m, ulong length, verylong za, verylong zalpha, verylong zp,
              verylong zq, verylong *zr, verylong *zs)
{
  struct SHA_1_struct data;
  ulong blocks, digest[5], i, left;
  verylong zi = 0, zk = 0, zt = 0, zu = 0, zv = 0;

  do zrandomb(zq, &zk); while (zscompare(zk, 0l) == 0);
  zexpmod(zalpha, zk, zp, &zt);
  zmod(zt, zq, zr);
  zinvmod(zk, zq, &zi);
  SHA_1_init(length, &data);
  blocks = length / 64l;
  left = blocks % 64l;
  for (i = 0; i < blocks; i++)
    SHA_1_update(m + i * 64l, &data);
  SHA_1_final(m + blocks * 64l, left, digest, &data);
  zone(&zt);
  for (i = 0; i < 5; i++) {
    zsmul(zt, digest[i], &zu);
    zcopy(zu, &zt);
  }
  zmul(za, *zr, &zt);
  zadd(zt, zu, &zv);
  zmulmod(zi, zv, zq, zs);
  zfree(&zi);
  zfree(&zk);
  zfree(&zt);
  zfree(&zu);
  zfree(&zv);
}

int DSA_verify(uchar *m, ulong length, verylong zalpha, verylong zp,
               verylong zq, verylong zr, verylong zs, verylong zy)
{
  int value;
  ulong blocks, digest[5], i, left;
  struct SHA_1_struct data;
  verylong zh = 0, zt = 0, zu = 0, zv = 0, zw = 0;
  verylong zu1 = 0, zu2 = 0;

  if (zscompare(zr, 0) == 0) return 0;
  if (zscompare(zs, 0) == 0) return 0;
  if (zcompare(zr, zq) >= 0) return 0;
  if (zcompare(zs, zq) >= 0) return 0;
  SHA_1_init(length, &data);
  blocks = length / 64l;
  left = blocks % 64l;
  for (i = 0; i < blocks; i++)
    SHA_1_update(m + i * 64l, &data);
  SHA_1_final(m + blocks * 64l, left, digest, &data);
  zone(&zt);
  for (i = 0; i < 5; i++) {
    zsmul(zt, digest[i], &zh);
    zcopy(zh, &zt);
  }
  zinvmod(zs, zq, &zw);
  zmulmod(zh, zw, zq, &zu1);
  zmulmod(zr, zw, zq, &zu2);
  zexpmod(zalpha, zu1, zp, &zt);
  zexpmod(zy, zu2, zp, &zu);
  zmulmod(zt, zu, zp, &zu1);
  zmod(zu1, zq, &zv);
  value = zcompare(zv, zr) == 0;
  zfree(&zh);
  zfree(&zt);
  zfree(&zu);
  zfree(&zv);
  zfree(&zw);
  zfree(&zu1);
  zfree(&zu2);
  return value;
}

int main(void)
{
  double time;
  clock_t time0 = clock();
  uchar m[1024] = "abc";
  verylong za = 0, zalpha = 0, zp = 0, zq = 0, zr = 0, zs = 0, zy = 0;

  DSA_gen_keys(0l, &za, &zalpha, &zp, &zq, &zy);
  time = (clock() - time0) / (double) CLK_TCK;
  printf("total time required: %lf\n", time);
  DSA_sign(m, 3l, za, zalpha, zp, zq, &zr, &zs);
  printf("%d ", DSA_verify(m, 3l, zalpha, zp, zq, zr, zs, zy));
  zfree(&za);
  zfree(&zalpha);
  zfree(&zp);
  zfree(&zq);
  zfree(&zr);
  zfree(&zs);
  zfree(&zy);
  return 0;
}
