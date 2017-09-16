/*
  Author:  Pate Williams (c) 1997

  Rabin public-key encryption. See "Handbook of
  Applied Cryptography" by Alfred J. Menezes et
  al Section 8.3 pages 292 - 294.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "lip.h"

#define BITS_PER_CHAR 8l
#define DEBUG

char MAGIC[32] = {1, 0, 1, 0, 1, 0, 1, 0,
                  1, 0, 1, 0, 1, 0, 1, 0,
                  1, 0, 1, 0, 1, 0, 1, 0,
                  1, 0, 1, 0, 1, 0, 1, 0};

int zsquare_root_mod(verylong za, verylong zp, verylong *zr)
{
  int value;
  long i, s = 0;
  verylong zb = 0, zc = 0, zd = 0, zi = 0;
  verylong zq = 0, zs = 0, zt = 0, zx = 0;

  if (zjacobi(za, zp) == - 1) {
    zzero(zr);
    value = 0;
  }
  else {
    do
      do zrandomb(zp, &zb); while (zscompare(zb, 0l) == 0);
    while (zjacobi(zb, zp) != - 1);
    zsadd(zp, - 1l, &zq);
    zcopy(zq, &zs);
    do {
      zrshift(zs, 1l, &zt);
      zcopy(zt, &zs);
      s++;
    } while (!zodd(zt));
    zinvmod(za, zp, &zi);
    zexpmod(zb, zt, zp, &zc);
    zsadd(zt, 1l, &zd);
    zcopy(zd, &zt);
    zrshift(zt, 1l, &zd);
    zexpmod(za, zd, zp, zr);
    for (i = 1; i <= s - 1; i++) {
      zone(&zt);
      zlshift(zt, s - i - 1, &zs);
      zmul(*zr, zi, &zt);
      zmul(*zr, zt, &zx);
      zexpmod(zx, zs, zp, &zd);
      if (zcompare(zq, zd) == 0) {
        zmulmod(*zr, zc, zp, &zt);
        zcopy(zt, zr);
      }
      zmulmod(zc, zc, zp, &zt);
      zcopy(zt, &zc);
    }
    value = 1;
  }
  zfree(&zb);
  zfree(&zc);
  zfree(&zd);
  zfree(&zi);
  zfree(&zq);
  zfree(&zs);
  zfree(&zt);
  zfree(&zx);
  return value;
}

int square_roots(verylong zf, verylong zn,
                 verylong zp, verylong zq,
                 verylong *zx1, verylong *zx2,
                 verylong *zy1, verylong *zy2)
/* computes the four square roots of a modulo n
   where n is composite n = p * q */
{
  int value;
  verylong za = 0, zb = 0, zc = 0, zd = 0, ze = 0;
  verylong zg = 0, zr = 0, zs = 0, zx = 0, zy = 0;

  zsquare_root_mod(zf, zp, &zr);
  zsquare_root_mod(zf, zq, &zs);
  zexteucl(zp, &zc, zq, &zd, &zg);
  if (zscompare(zr, 0l) != 0 && zscompare(zs, 0l) != 0 &&
      zscompare(zg, 1l) == 0) {
    zmul(zr, zd, &za);
    zmul(za, zq, &zb);
    zmul(zs, zc, &za);
    zmul(za, zp, &ze);
    zaddmod(zb, ze, zn, &zx);
    zmul(zr, zd, &za);
    zmul(za, zq, &zb);
    zmul(zs, zc, &za);
    zmul(za, zp, &ze);
    zsubmod(zb, ze, zn, &zy);
    zmod(zx, zn, zx1);
    znegate(&zx);
    zmod(zx, zn, zx2);
    zmod(zy, zn, zy1);
    znegate(&zy);
    zmod(zy, zn, zy2);
    value = 1;
  }
  else value = 0;
  zfree(&za);
  zfree(&zb);
  zfree(&zc);
  zfree(&zd);
  zfree(&ze);
  zfree(&zg);
  zfree(&zr);
  zfree(&zs);
  zfree(&zx);
  zfree(&zy);
  return value;
}

int get_bit(char *buffer, long number)
{
  long bit = number % BITS_PER_CHAR;
  long byte = number / BITS_PER_CHAR;

  return (buffer[byte] >> bit) & 1;
}

void set_bit(char *buffer, int value, long number)
{
  long bit = number % BITS_PER_CHAR;
  long byte = number / BITS_PER_CHAR;
  long mask;

  if (value == 1)
    buffer[byte] |= (char) (1 << bit);
  else {
    mask = 1 << bit;
    buffer[byte] &= (char) ~mask;
  }
}

void bits_to_verylong(char *bits, long number, verylong *za)
{
  long i;
  verylong zb = 0;

  zintoz(bits[0] - '0', za);
  for (i = 1; i < number; i++) {
    zlshift(*za, 1l, &zb);
    zsadd(zb, bits[i] - '0', za);
  }
  zfree(&zb);
}

void verylong_to_bits(char *bits, long *number, verylong za)
{
  long i;
  verylong zb = 0, zc = 0;

  *number = z2log(za);
  zcopy(za, &zb);
  for (i = 0; i < *number; i++) {
    zlowbits(zb, 1l, &zc);
    bits[i] = (char) ((zc[1] & 1) + '0');
    zrshift(zb, 1l, &zc);
    zcopy(zc, &zb);
  }
  bits[*number] = 0;
  strrev(bits);
  zfree(&zb);
  zfree(&zc);
}

long OddRandom(long bit_length)
{
  long i, mask = 1, n;

  bit_length--;
  for (i = 1; i <= bit_length; i++)
    mask |= 1 << i;
  if (bit_length < 16)
    n = (1 << bit_length) | rand();
  else
    n = (1 << bit_length) | (rand() << 16) | rand();
  n &= mask;
  if ((n & 1) == 0) n++;
  return n;
}

void PROVABLE_PRIME(long k, verylong *zn)
{
  double c, r, s;
  int success;
  long B, m, n, p, sqrtn;
  verylong zI = 0, zR = 0, za = 0, zb = 0, zc = 0;
  verylong zd = 0, zk = 0, zl = 0, zq = 0, zu = 0;

  srand(time(NULL));
  zrstarts(time(NULL));
  if (k <= 20) {
    do {
      n = OddRandom(k);
      sqrtn = sqrt(n);
      zpstart2();
      do p = zpnext(); while (n % p != 0 && p < sqrtn);
    } while (p < sqrtn);
    zintoz(n, zn);
  }
  else {
    c = 0.1;
    m = 20;
    B = c * k * k;
    if (k > 2 * m)
      do {
        s = rand() / (double) RAND_MAX;
        r = pow(2.0, s - 1.0);
      } while (k - r * k <= m);
    else
      r = 0.5;
    PROVABLE_PRIME(r * k + 1, &zq);
    zone(&za);
    zlshift(za, k - 1, &zk);
    zcopy(zq, &za);
    zlshift(za, 1l, &zl);
    zdiv(zk, zl, &zI, &za);
    zsadd(zI, 1l, &zl);
    zlshift(zI, 1l, &zu);
    success = 0;
    while (!success) {
      do zrandomb(zu, &zR); while (zcompare(zR, zl) < 0);
      zmul(zR, zq, &za);
      zlshift(za, 1l, &zb);
      zsadd(zb, 1l, zn);
      zcopy(zR, &za);
      zlshift(za, 1l, &zR);
      zpstart2();
      p = zpnext();
      while (zsmod(*zn, p) != 0 && p < B) p = zpnext();
      if (p >= B) {
        zcopy(*zn, &zc);
        zsadd(zc, - 2l, &zb);
        do
          zrandomb(*zn, &za);
        while (zscompare(za, 2l) < 0 || zcompare(za, zb) > 0);
        zsadd(*zn, - 1l, &zc);
        zexpmod(za, zc, *zn, &zb);
        if (zscompare(zb, 1l) == 0) {
          zexpmod(za, zR, *zn, &zb);
          zcopy(zb, &zd);
          zsadd(zd, - 1l, &zb);
          zgcd(zb, *zn, &zd);
          success = zscompare(zd, 1l) == 0;
        }
      }
    }
  }
  zfree(&zI);
  zfree(&zR);
  zfree(&za);
  zfree(&zb);
  zfree(&zc);
  zfree(&zd);
  zfree(&zk);
  zfree(&zl);
  zfree(&zq);
  zfree(&zu);
}

void Rabin_gen_keys(long length, verylong *zn,
                    verylong *zp, verylong *zq)
{
  PROVABLE_PRIME(length, zp);
  PROVABLE_PRIME(length, zq);
  zmul(*zp, *zq, zn);
}

void Rabin_encryption(char *inp, char *out,
                      long inp_len, long *left,
                      long *out_len, verylong zn)
/* inp_len is the length of the input buffer in bytes
   out_len is the length of the output buffer in bits */
{
  long out_bit_length = z2log(zn);
  long inp_bit_length = out_bit_length - 1l;
  long b = inp_len << 3;
  long blocks = b / (inp_bit_length - 32l);
  long inp_i = 0, out_i = 0, j, k, l;
  char *bits = calloc(out_bit_length + 1, sizeof(char));
  verylong za = 0, zc = 0, zm = 0;

  *left = b % (inp_bit_length - 32l);
  for (j = 0; j < blocks; j++) {
    for (k = 0; k < 32l; k++)
      bits[k] = (char) (MAGIC[k] + '0');
    for (k = 32l; k < inp_bit_length; k++)
      bits[k] = (char) (get_bit(inp, inp_i++) + '0');
    bits_to_verylong(bits, inp_bit_length, &zm);
    zmulmod(zm, zm, zn, &zc);
    verylong_to_bits(bits, &l, zc);
    for (k = 0; k < out_bit_length - l; k++)
      set_bit(out, 0, out_i++);
    for (k = 0; k < l; k++)
      set_bit(out, bits[k] - '0', out_i++);
  }
  if (*left > 0) {
    for (j = 0; j < 32l; j++)
      bits[j] = (char) (MAGIC[j] + '0');
    for (j = 0; j < *left; j++)
      bits[32l + j] =(char) (get_bit(inp, inp_i++) + '0');
    bits_to_verylong(bits, *left + 32l, &zm);
    zmulmod(zm, zm, zn, &zc);
    verylong_to_bits(bits, &l, zc);
    for (k = 0; k < out_bit_length - l; k++)
      set_bit(out, 0, out_i++);
    for (k = 0; k < l; k++)
      set_bit(out, bits[k] - '0', out_i++);
  }
  *out_len = out_i;
  free(bits);
  zfree(&za);
  zfree(&zc);
  zfree(&zm);
}

void Rabin_decryption(char *inp, char *out, long inp_len,
                      long left, long *out_len,
                      verylong zn, verylong zp,
                      verylong zq)
/* inp_len is the length of the input buffer in bits
   out_len is the length of the output buffer in bytes */
{
  int equal, found;
  long inp_bit_length = z2log(zn);
  long out_bit_length = inp_bit_length - 33l;
  long blocks = inp_len / inp_bit_length;
  long inp_i = 0, out_i = 0, j, k, kmax, l, m;
  char *bits = calloc(inp_bit_length + 1, sizeof(char));
  verylong za = 0, zb = 0, zc = 0, zm[4];

  zm[0] = zm[1] = zm[2] = zm[3] = 0;
  for (j = 0; j < blocks; j++) {
    for (k = 0; k < inp_bit_length; k++)
      bits[k] = (char) (get_bit(inp, inp_i++) + '0');
    bits_to_verylong(bits, inp_bit_length, &zc);
    square_roots(zc, zn, zp, zq, &zm[0], &zm[1], &zm[2], &zm[3]);
    found = 0;
    for (k = 0; k < 4 && !found; k++) {
      verylong_to_bits(bits, &l, zm[k]);
      equal = 1;
      for (m = 0; m < 32l && equal; m++)
        equal = (bits[m] - '0') == MAGIC[m];
      found = equal;
    }
    if (!found) {
      printf("*error*\nmagic not found!\n");
      exit(1);
    }
    if (j == (blocks - 1) && left != 0) kmax = left;
    else kmax = out_bit_length;
    for (k = 0; k < kmax - l; k++)
      set_bit(out, 0, out_i++);
    for (k = 32l; k < l; k++)
      set_bit(out, bits[k] - '0', out_i++);
  }
  *out_len = out_i >> 3;
  free(bits);
  zfree(&za);
  zfree(&zb);
  zfree(&zc);
  for (j = 0; j < 4; j++) zfree(&zm[j]);
}

int main(void)
{
  char alphabet[32] = "abcdefghijklmnopqrstuvwxyz";
  char inp[1024] = {0}, out[1024]= {0};
  long i, inp_len = 260, left, out_len;
  verylong zn = 0, zp = 0, zq = 0;

  for (i = 0; i < 10l; i++)
    strcpy(inp + 26l * i, alphabet);
  Rabin_gen_keys(97l, &zn, &zp, &zq);
  Rabin_encryption(inp, out, inp_len, &left, &out_len, zn);
  Rabin_decryption(out, inp, out_len, left, &inp_len, zn, zp, zq);
  inp[inp_len] = 0;
  printf("%s\n", inp);
  zfree(&zn);
  zfree(&zp);
  zfree(&zq);
  return 0;
}
