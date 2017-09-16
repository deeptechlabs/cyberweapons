/*
  Author:  Pate Williams (c) 1997

  ElGamal public-key encryption. See "Handbook of
  Applied Cryptography" by Alfred J. Menezes et al
  8.4 Section pages 294 - 296.
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

void generator(long k, verylong zn, verylong *za,
               verylong *zp)
/* find a generator a of the cyclic group of order n
   where the factorization of n is known */
{
  long i;
  verylong zb = 0, zc = 0, zr = 0;

  L:
    zrandomb(zn, za);
    i = 0;
    M:
      zdiv(zn, zp[i], &zc, &zr);
      zexpmod(*za, zc, zn, &zb);
      if (zscompare(zb, 1l) == 0) goto L;
      i++;
      if (i < k) goto M;
  zfree(&zb);
  zfree(&zc);
  zfree(&zr);
}

void ElGamal_gen_keys(long length, verylong *za,
                      verylong *zaa, verylong *zc,
                      verylong *zp)
{
  long k = length - 1;
  verylong zb = 0, zn = 0, zq = 0, zr[2];

  zr[0] = zr[1] = 0;
  zrstarts(time(NULL));
  do {
	zrandomprime(length, 18l, &zq, zrandomb);
    zlshift(zq, 1l, &zb);
    zsadd(zb, 1l, zp);
  } while (!zprobprime(*zp, 18l));
  zsadd(*zp, - 1l, &zn);
  k = 2;
  zintoz(2l, &zr[0]);
  zcopy(zq, &zr[1]);
  generator(k, zn, za, zr);
  do zrandomb(zn, zc); while (zscompare(*zc, 0l) == 0);
  zexpmod(*za, *zc, *zp, zaa);
  zfree(&zb);
  zfree(&zn);
  zfree(&zq);
  zfree(&zr[0]);
  zfree(&zr[1]);
}

void ElGamal_encryption(char *inp, char *out, long inp_len,
                        long *left, long *out_len,
                        verylong za, verylong zaa,
                        verylong zp)
/* inp_len is the length of the input buffer in bytes
   out_len is the length of the output buffer in bits */
{
  long out_bit_length = z2log(zp), inp_bit_length = out_bit_length - 1;
  long b = inp_len << 3;
  long blocks = b / inp_bit_length;
  long inp_i = 0, out_i = 0, i, j, k;
  char *bits = calloc(out_bit_length + 1, sizeof(char));
  verylong zc = 0, zd = 0, zg = 0, zk = 0, zm = 0, zn = 0;

  *left = b % inp_bit_length;
  zsadd(zp, - 1l, &zn);
  for (i = 0; i < blocks; i++) {
    for (j = 0; j < inp_bit_length; j++)
      bits[j] = (char) (get_bit(inp, inp_i++) + '0');
    bits_to_verylong(bits, inp_bit_length, &zm);
    do zrandomb(zn, &zk); while(zscompare(zk, 0l) == 0);
    zexpmod(za, zk, zp, &zg);
    zexpmod(zaa, zk, zp, &zc);
    zmulmod(zm, zc, zp, &zd);
    verylong_to_bits(bits, &k, zg);
    for (j = 0; j < out_bit_length - k; j++)
      set_bit(out, 0, out_i++);
    for (j = 0; j < k; j++)
      set_bit(out, bits[j] - '0', out_i++);
    verylong_to_bits(bits, &k, zd);
    for (j = 0; j < out_bit_length - k; j++)
      set_bit(out, 0, out_i++);
    for (j = 0; j < k; j++)
      set_bit(out, bits[j] - '0', out_i++);
  }
  if (*left > 0) {
    for (j = 0; j < *left; j++)
      bits[j] = (char) (get_bit(inp, inp_i++) + '0');
    bits_to_verylong(bits, *left, &zm);
    do zrandomb(zn, &zk); while(zscompare(zk, 0l) == 0);
    zexpmod(za, zk, zp, &zg);
    zexpmod(zaa, zk, zp, &zc);
    zmulmod(zm, zc, zp, &zd);
    verylong_to_bits(bits, &k, zg);
    for (j = 0; j < out_bit_length - k; j++)
      set_bit(out, 0, out_i++);
    for (j = 0; j < k; j++)
      set_bit(out, bits[j] - '0', out_i++);
    verylong_to_bits(bits, &k, zd);
    for (j = 0; j < out_bit_length - k; j++)
      set_bit(out, 0, out_i++);
    for (j = 0; j < k; j++)
      set_bit(out, bits[j] - '0', out_i++);
  }
  *out_len = out_i;
  zfree(&zc);
  zfree(&zd);
  zfree(&zg);
  zfree(&zk);
  zfree(&zm);
  zfree(&zn);
}

void ElGamal_decryption(char *inp, char *out, long inp_len,
                        long left, long *out_len,
                        verylong zc, verylong zp)
/* inp_len is the length of the input buffer in bits
   out_len is the length of the output buffer in bytes */
{
  long inp_bit_length = z2log(zp), out_bit_length = inp_bit_length - 1;
  long blocks = inp_len / (2 * inp_bit_length);
  long inp_i = 0, out_i = 0, i, j, jmax, k;
  char *bits = calloc(inp_bit_length + 1, sizeof(char));
  verylong zd = 0, ze = 0, zg = 0, zm = 0, zn = 0;

  zsadd(zp, - 1l, &zn);
  zsub(zn, zc, &ze);
  for (i = 0; i < blocks; i++) {
    for (j = 0; j < inp_bit_length; j++)
      bits[j] = (char) (get_bit(inp, inp_i++) + '0');
    bits_to_verylong(bits, inp_bit_length, &zg);
    for (j = 0; j < inp_bit_length; j++)
      bits[j] = (char) (get_bit(inp, inp_i++) + '0');
    bits_to_verylong(bits, inp_bit_length, &zd);
    zexpmod(zg, ze, zp, &zn);
    zmulmod(zn, zd, zp, &zm);
    verylong_to_bits(bits, &k, zm);
    if (i == blocks - 1 && left != 0) jmax = left;
    else jmax = out_bit_length;
    for (j = 0; j < jmax - k; j++)
      set_bit(out, 0, out_i++);
    for (j = 0; j < k; j++)
      set_bit(out, bits[j] - '0', out_i++);
  }
  *out_len = out_i >> 3;
  zfree(&zd);
  zfree(&ze);
  zfree(&zg);
  zfree(&zm);
  zfree(&zn);
}

int main(void)
{
  char alphabet[32] = "abcdefghijklmnopqrstuvwxyz";
  char inp[4096] = {0}, out[4096]= {0};
  long i, inp_len = 260, left, out_len;
  verylong za = 0, zaa = 0, zc = 0, zp = 0;

  for (i = 0; i < 10l; i++)
    strcpy(inp + 26l * i, alphabet);
  ElGamal_gen_keys(511l, &za, &zaa, &zc, &zp);
  ElGamal_encryption(inp, out, inp_len, &left, &out_len, za, zaa, zp);
  ElGamal_decryption(out, inp, out_len, left, &inp_len, zc, zp);
  inp[inp_len] = 0;
  printf("%s\n", inp);
  printf("prime (bit length: %d)\n", z2log(zp));
  zwriteln(zp);
  zfree(&za);
  zfree(&zc);
  zfree(&zp);
  zfree(&zaa);
  return 0;
}