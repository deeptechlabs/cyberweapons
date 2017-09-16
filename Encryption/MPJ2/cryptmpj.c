/* cryptmpj.c - Encryption designed to exceed DES in security.
   The MPJ2 encryption algorithm is in the public domain.
*/

#include <stdio.h>
#include <stdlib.h>
#include <mem.h>
#include "def.h"
#include "cryptmpj.h"
#include "crc.h"

static byte *key = NULL;
static uint keysize;
static uint keyindex;
static unsigned long accum;
static uint numrounds;
static byte *s;             /* Substitution boxes. */
static byte *si;            /* Inverse substitution boxes. */

uint keyrand(uint max_value)    // Returns uniformly distributed pseudorandom
    {                           // value based on key[], sized keysize
    uint prandvalue, i;
    unsigned long mask;
    
    if (!max_value) return 0;
    mask = 0L;              // Create a mask to get the minimum
    for (i=max_value; i > 0; i = i >> 1)    // number of bits to cover the
        mask = (mask << 1) | 1L;        // range 0 to max_value.
    i=0;
    do
        {
        accum = crc32(accum, key[keyindex++]);
        if (keyindex >= keysize) keyindex = 0;  // Recycle thru the key
        prandvalue = (uint) (accum & mask);
        if ((++i>97) && (prandvalue > max_value))   // Don't loop forever.
            prandvalue -= max_value;                // Introduce negligible bias.
        }
    while (prandvalue > max_value); // Discard out of range values.
    return prandvalue;
    }

static void makeonebox(uint i, uint j)
    {
    int n;
    uint pos, m, p;
    boolean filled[256];

    for (m = 0; m < 256; m++)   /* The filled array is used to make sure that */
        filled[m] = false;      /* each byte of the array is filled only once. */
    for (n = 255; n >= 0 ; n--) /* n counts the number of bytes left to fill */
        {
        pos = keyrand(n);   /* pos is the position among the UNFILLED */
                            /* components of the s array that the */
                            /* number n should be placed.  */
        p=0;
        while (filled[p]) p++;
        for (m=0; m<pos; m++)
            {
            p++;
            while (filled[p]) p++;
            }
        *(s + (4096*i) + (256*j) + p) = n;
        filled[p] = true;
        }
    }

void set_mpj_key(byte *external_key, uint key_size, uint rounds, boolean invert)
/* This procedure generates internal keys by filling the substitution box array
  s based on the external key given as input.  It DOES take a bit of time. */
  {
    uint i, j, k;

    numrounds = rounds;
    if ((numrounds < 5) || (numrounds > 15))
        {
        puts("Numrounds out of range in set_mpj_key()");
        exit(10);
        }
    if (BuildCRCTable())
        {
        puts("Not enough memory.");
        exit(5);
        }
    if (s) mpj_done();
    s=(byte *) malloc(numrounds * 4096U);
    if (!s)
        {
        puts("Out of memory.");
        exit(5);
        }
    key = external_key;
    keysize = key_size;
    accum = 0xFFFFFFFFL;

    for (i = 0; i < numrounds; i++)
        {
        for (j = 0; j < 16; j++)
            {
            makeonebox(i, j);
            }
        }
    if (invert)
        {   /* Fill the inverse substitution box array si.  It is not
               necessary to do this unless the decryption mode is used.  */
        si=(byte *) malloc(numrounds * 4096U);
        if (!si)
            {
            puts("Out of memory.");
            exit(5);
            }
        for (i = 0; i < numrounds; i++)
            {
            for (j = 0; j < 16; j++)
                {
                for (k = 0; k < 256; k++)
                    {
                    *(si + (4096 * i) + (256 * j) + *(s + (4096 * i) + (256 * j) + k)) = k;
                    }
                }
            }
        }
    }

static void permute(byte *x, byte *y)   // x and y must be different.
/* This procedure is designed to make each bit of the output dependent on as
  many bytes of the input as possible, especially after repeated application.
  Each output byte takes its least significant bit from the corresponding
  input byte.  The next higher bit comes from the corresponding bit of the
  input byte to the left.  This is done until all bits of the output byte
  are filled.  Where there is no byte to the left, the byte at the far right
  is used. */
    {
    y[0] = (x[0] & 1) | (x[1] & 2) | (x[2] & 4) |
            (x[3] & 8) | (x[4] & 16) | (x[5] & 32) |
            (x[6] & 64) | (x[7] & 128);
    y[1] = (x[1] & 1) | (x[2] & 2) | (x[3] & 4) |
            (x[4] & 8) | (x[5] & 16) | (x[6] & 32) |
            (x[7] & 64) | (x[8] & 128);
    y[2] = (x[2] & 1) | (x[3] & 2) | (x[4] & 4) |
            (x[5] & 8) | (x[6] & 16) | (x[7] & 32) |
            (x[8] & 64) | (x[9] & 128);
    y[3] = (x[3] & 1) | (x[4] & 2) | (x[5] & 4) |
            (x[6] & 8) | (x[7] & 16) | (x[8] & 32) |
            (x[9] & 64) | (x[10] & 128);
    y[4] = (x[4] & 1) | (x[5] & 2) | (x[6] & 4) |
            (x[7] & 8) | (x[8] & 16) | (x[9] & 32) |
            (x[10] & 64) | (x[11] & 128);
    y[5] = (x[5] & 1) | (x[6] & 2) | (x[7] & 4) |
            (x[8] & 8) | (x[9] & 16) | (x[10] & 32) |
            (x[11] & 64) | (x[12] & 128);
    y[6] = (x[6] & 1) | (x[7] & 2) | (x[8] & 4) |
            (x[9] & 8) | (x[10] & 16) | (x[11] & 32) |
            (x[12] & 64) | (x[13] & 128);
    y[7] = (x[7] & 1) | (x[8] & 2) | (x[9] & 4) |
            (x[10] & 8) | (x[11] & 16) | (x[12] & 32) |
            (x[13] & 64) | (x[14] & 128);
    y[8] = (x[8] & 1) | (x[9] & 2) | (x[10] & 4) |
            (x[11] & 8) | (x[12] & 16) | (x[13] & 32) |
            (x[14] & 64) | (x[15] & 128);
    y[9] = (x[9] & 1) | (x[10] & 2) | (x[11] & 4) |
            (x[12] & 8) | (x[13] & 16) | (x[14] & 32) |
            (x[15] & 64) | (x[0] & 128);
    y[10] = (x[10] & 1) | (x[11] & 2) | (x[12] & 4) |
            (x[13] & 8) | (x[14] & 16) | (x[15] & 32) |
            (x[0] & 64) | (x[1] & 128);
    y[11] = (x[11] & 1) | (x[12] & 2) | (x[13] & 4) |
            (x[14] & 8) | (x[15] & 16) | (x[0] & 32) |
            (x[1] & 64) | (x[2] & 128);
    y[12] = (x[12] & 1) | (x[13] & 2) | (x[14] & 4) |
            (x[15] & 8) | (x[0] & 16) | (x[1] & 32) |
            (x[2] & 64) | (x[3] & 128);
    y[13] = (x[13] & 1) | (x[14] & 2) | (x[15] & 4) |
            (x[0] & 8) | (x[1] & 16) | (x[2] & 32) |
            (x[3] & 64) | (x[4] & 128);
    y[14] = (x[14] & 1) | (x[15] & 2) | (x[0] & 4) |
            (x[1] & 8) | (x[2] & 16) | (x[3] & 32) |
            (x[4] & 64) | (x[5] & 128);
    y[15] = (x[15] & 1) | (x[0] & 2) | (x[1] & 4) |
            (x[2] & 8) | (x[3] & 16) | (x[4] & 32) |
            (x[5] & 64) | (x[6] & 128);
    }

static void ipermute(byte *x, byte *y) /* x!=y */
/* This is the inverse of the procedure permute. */
    {
    y[0] = (x[0] & 1) | (x[15] & 2) | (x[14] & 4) |
            (x[13] & 8) | (x[12] & 16) | (x[11] & 32) |
            (x[10] & 64) | (x[9] & 128);
    y[1] = (x[1] & 1) | (x[0] & 2) | (x[15] & 4) |
            (x[14] & 8) | (x[13] & 16) | (x[12] & 32) |
            (x[11] & 64) | (x[10] & 128);
    y[2] = (x[2] & 1) | (x[1] & 2) | (x[0] & 4) |
            (x[15] & 8) | (x[14] & 16) | (x[13] & 32) |
            (x[12] & 64) | (x[11] & 128);
    y[3] = (x[3] & 1) | (x[2] & 2) | (x[1] & 4) |
            (x[0] & 8) | (x[15] & 16) | (x[14] & 32) |
            (x[13] & 64) | (x[12] & 128);
    y[4] = (x[4] & 1) | (x[3] & 2) | (x[2] & 4) |
            (x[1] & 8) | (x[0] & 16) | (x[15] & 32) |
            (x[14] & 64) | (x[13] & 128);
    y[5] = (x[5] & 1) | (x[4] & 2) | (x[3] & 4) |
            (x[2] & 8) | (x[1] & 16) | (x[0] & 32) |
            (x[15] & 64) | (x[14] & 128);
    y[6] = (x[6] & 1) | (x[5] & 2) | (x[4] & 4) |
            (x[3] & 8) | (x[2] & 16) | (x[1] & 32) |
            (x[0] & 64) | (x[15] & 128);
    y[7] = (x[7] & 1) | (x[6] & 2) | (x[5] & 4) |
            (x[4] & 8) | (x[3] & 16) | (x[2] & 32) |
            (x[1] & 64) | (x[0] & 128);
    y[8] = (x[8] & 1) | (x[7] & 2) | (x[6] & 4) |
            (x[5] & 8) | (x[4] & 16) | (x[3] & 32) |
            (x[2] & 64) | (x[1] & 128);
    y[9] = (x[9] & 1) | (x[8] & 2) | (x[7] & 4) |
            (x[6] & 8) | (x[5] & 16) | (x[4] & 32) |
            (x[3] & 64) | (x[2] & 128);
    y[10] = (x[10] & 1) | (x[9] & 2) | (x[8] & 4) |
            (x[7] & 8) | (x[6] & 16) | (x[5] & 32) |
            (x[4] & 64) | (x[3] & 128);
    y[11] = (x[11] & 1) | (x[10] & 2) | (x[9] & 4) |
            (x[8] & 8) | (x[7] & 16) | (x[6] & 32) |
            (x[5] & 64) | (x[4] & 128);
    y[12] = (x[12] & 1) | (x[11] & 2) | (x[10] & 4) |
            (x[9] & 8) | (x[8] & 16) | (x[7] & 32) |
            (x[6] & 64) | (x[5] & 128);
    y[13] = (x[13] & 1) | (x[12] & 2) | (x[11] & 4) |
            (x[10] & 8) | (x[9] & 16) | (x[8] & 32) |
            (x[7] & 64) | (x[6] & 128);
    y[14] = (x[14] & 1) | (x[13] & 2) | (x[12] & 4) |
            (x[11] & 8) | (x[10] & 16) | (x[9] & 32) |
            (x[8] & 64) | (x[7] & 128);
    y[15] = (x[15] & 1) | (x[14] & 2) | (x[13] & 4) |
            (x[12] & 8) | (x[11] & 16) | (x[10] & 32) |
            (x[9] & 64) | (x[8] & 128);
    }

static void substitute(uint round, byte *x, byte *y)
    {
    uint i;

    for (i = 0; i < 16; i++)
        y[i] = *(s + (4096*round) + (256*i) + x[i]);
    }

static void isubst(uint round, byte *x, byte *y)
    {
    uint i;

    for (i = 0; i < 16; i++)
        y[i] = *(si + (4096*round) + (256*i) + x[i]);
    }

void mpj_encrypt_block(byte *x, byte *y)
/* Encrypt a block of 16 bytes. */
    {
    uint round;
    byte z[16];

    substitute(0, x, y);
    for (round=1; round < numrounds; round++)
        {
        permute(y, z);
        substitute(round, z, y);
        }
    }

void mpj_decrypt_block(byte *x, byte *y)
/* Decrypt a block of 16 bytes. */
    {
    int round;
    byte z[16];
    
    isubst(numrounds-1, x, y);
    for (round=numrounds-2; round >= 0; round--)
        {
        ipermute(y, z);
        isubst(round, z, y);
        }
    }

void mpj_done(void)
    {
    if (s)
        {
        memset(s, 0, 40960U);
        free(s);
        s=NULL;
        }
    if (si)
        {
        memset(si, 0, 40960U);
        free(si);
        s=NULL;
        }
    }

