/*
  Author:  Pate Williams (c) 1997

  RSA public-key encryption. See "Handbook of
  Applied Cryptography" by Alfred J. Menezes et
  al 8.2 Section pages 285 - 287.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "\freelip\lip.h"

#define BITS_PER_CHAR 8l

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

void RSA_gen_keys(long length, verylong *zd,
                  verylong *ze, verylong *zn)
{
  verylong zp = 0, zp1 = 0, zq = 0, zq1 = 0;
  verylong zphi = 0, zx = 0;

  srand(time(NULL));
  zrstarts(time(NULL));
  PROVABLE_PRIME(length, &zp);
  PROVABLE_PRIME(length, &zq);
  zmul(zp, zq, zn);
  zsadd(zp, - 1l, &zp1);
  zsadd(zq, - 1l, &zq1);
  zmul(zp1, zq1, &zphi);
  do {
    do zrandomb(zphi, ze); while (zscompare(*ze, 1l) <= 0);
    zgcd(*ze, zphi, &zx);
  } while (zscompare(zx, 1l) != 0);
  zinvmod(*ze, zphi, zd);
  zfree(&zp);
  zfree(&zq);
  zfree(&zp1);
  zfree(&zq1);
  zfree(&zphi);
  zfree(&zx);
}

void RSA_encryption(char *inp, char *out, long inp_len,
                    long *left, long *out_len,
                    verylong ze, verylong zn)
/* inp_len is the length of the input buffer in bytes
   out_len is the length of the output buffer in bits */
{
  long out_bit_length = z2log(zn), inp_bit_length = out_bit_length - 1;
  long b = inp_len << 3;
  long blocks = b / inp_bit_length;
  long inp_i = 0, out_i = 0, i, j, k;
  char *bits = calloc(out_bit_length + 1, sizeof(char));
  verylong zc = 0, zm = 0;

  *left = b % inp_bit_length;
  for (i = 0; i < blocks; i++) {
    for (j = 0; j < inp_bit_length; j++)
      bits[j] = (char) (get_bit(inp, inp_i++) + '0');
    bits_to_verylong(bits, inp_bit_length, &zm);
    zexpmod(zm, ze, zn, &zc);
    verylong_to_bits(bits, &k, zc);
    for (j = 0; j < out_bit_length - k; j++)
      set_bit(out, 0, out_i++);
    for (j = 0; j < k; j++)
      set_bit(out, bits[j] - '0', out_i++);
  }
  if (*left > 0) {
    for (j = 0; j < *left; j++)
      bits[j] = (char) (get_bit(inp, inp_i++) + '0');
    bits_to_verylong(bits, *left, &zm);
    zexpmod(zm, ze, zn, &zc);
    verylong_to_bits(bits, &k, zc);
    for (j = 0; j < out_bit_length - k; j++)
      set_bit(out, 0, out_i++);
    for (j = 0; j < k; j++)
      set_bit(out, bits[j] - '0', out_i++);
  }
  *out_len = out_i;
  zfree(&zc);
  zfree(&zm);
}

void RSA_decryption(char *inp, char *out, long inp_len,
                    long left, long *out_len,
                    verylong zd, verylong zn)
/* inp_len is the length of the input buffer in bits
   out_len is the length of the output buffer in bytes */
{
  long inp_bit_length = z2log(zn), out_bit_length = inp_bit_length - 1;
  long blocks = inp_len / inp_bit_length;
  long inp_i = 0, out_i = 0, i, j, jmax, k;
  char *bits = calloc(inp_bit_length + 1, sizeof(char));
  verylong zc = 0, zm = 0;

  for (i = 0; i < blocks; i++) {
    for (j = 0; j < inp_bit_length; j++)
      bits[j] = (char) (get_bit(inp, inp_i++) + '0');
    bits_to_verylong(bits, inp_bit_length, &zc);
    zexpmod(zc, zd, zn, &zm);
    verylong_to_bits(bits, &k, zm);
    if (i == blocks - 1 && left != 0) jmax = left;
    else jmax = out_bit_length;
    for (j = 0; j < jmax - k; j++)
      set_bit(out, 0, out_i++);
    for (j = 0; j < k; j++)
      set_bit(out, bits[j] - '0', out_i++);
  }
  *out_len = out_i >> 3;
  zfree(&zc);
  zfree(&zm);
}

int main(void)
{
  char alphabet[32] = "abcdefghijklmnopqrstuvwxyz";
  char inp[4096] = {0}, out[4096]= {0};
  long i, inp_len = 260, left, out_len;
  verylong zd = 0, ze = 0, zn = 0;

  for (i = 0; i < 10l; i++)
    strcpy(inp + 26l * i, alphabet);
  RSA_gen_keys(512l, &zd, &ze, &zn);
  RSA_encryption(inp, out, inp_len, &left, &out_len, ze, zn);
  RSA_decryption(out, inp, out_len, left, &inp_len, zd, zn);
  inp[inp_len] = 0;
  printf("%s\n", inp);
  zfree(&zd);
  zfree(&ze);
  zfree(&zn);
  return 0;
}
