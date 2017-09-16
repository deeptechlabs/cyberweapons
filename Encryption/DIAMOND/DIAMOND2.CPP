/* diamond2.c - Encryption designed to exceed DES in security.
   This file and the Diamond2 and Diamond2 Lite Block Ciphers
   described herein are hereby dedicated to the Public Domain by the
   author and inventor, Michael Paul Johnson.  Feel free to use these
   for any purpose that is legally and morally right.  The names
   "Diamond2 Block Cipher" and "Diamond2 Lite Block Cipher" should only
   be used to describe the algorithms described in this file, to avoid
   confusion.

   Disclaimers:  the following comes with no warranty, expressed or
   implied.  You, the user, must determine the suitability of this
   information to your own uses.  You must also find out what legal
   requirements exist with respect to this data and programs using
   it, and comply with whatever valid requirements exist.
*/
#include <stdio.h>
#include <stdlib.h>
#ifdef UNIX
#include <memory.h>
#else
#include <mem.h>
#endif
#include "def.h"
#include "diamond2.h"
#include "crc.h"

static byte *key = NULL;
static uint keysize;
static uint keyindex;
static uint roundsize;          /* Number of bytes in one round of substitution boxes. */
static int blocksize;           /* Number of bytes in a block. */
static unsigned long accum;
static uint numrounds;
static byte *s = NULL;             /* Substitution boxes. */
static byte *si = NULL;            /* Inverse substitution boxes. */

static uint keyrand(uint max_value, byte *sbox)    /* Returns uniformly distributed pseudorandom */
    {                           /* value based on key[], sized keysize */
    uint prandvalue, i;		/* Change from Diamond to Diamond 2: use of */
    unsigned long mask;		/* sbox (previous 256-byte permutation array)*/
    
    if (!max_value) return 0;
    mask = 0L;              /* Create a mask to get the minimum */
    for (i=max_value; i > 0; i = i >> 1)    /* number of bits to cover the */
        mask = (mask << 1) | 1L;        /* range 0 to max_value. */
    i=0;
    do
        {
	if (sbox)
	    accum = crc32(accum, sbox[key[keyindex++]]);
	else
	    accum = crc32(accum, key[keyindex++]);
        if (keyindex >= keysize)
            {
            keyindex = 0;   /* Recycle thru the key */
            accum = crc32(accum, (keysize & 0xFF));
            accum = crc32(accum, ((keysize >> 8) & 0xFF));
            }
        prandvalue = (uint) (accum & mask);
        if ((++i>97) && (prandvalue > max_value))   /* Don't loop forever. */
            prandvalue -= max_value;                /* Introduce negligible bias. */
        }
    while (prandvalue > max_value); /* Discard out of range values. */
    return prandvalue;
    }

static void makeonebox(uint i, uint j, byte *sbox)
    {	/* Change from Diamond to Diamond 2: use of sbox. */
	    /* sbox is either NULL or a pointer to the previously filled array. */
    int n;
    uint pos, m, p;
    boolean filled[256];

    for (m = 0; m < 256; m++)   /* The filled array is used to make sure that */
        filled[m] = false;      /* each byte of the array is filled only once. */
    for (n = 255; n >= 0 ; n--) /* n counts the number of bytes left to fill */
        {
        pos = keyrand(n, sbox); /* pos is the position among the UNFILLED */
                                /* components of the s array that the */
                                /* number n should be placed.  */
        p=0;
        while (filled[p]) p++;
        for (m=0; m<pos; m++)
            {
            p++;
            while (filled[p]) p++;
            }
        *(s + (roundsize*i) + (256*j) + p) = n;
        filled[p] = true;
        }
    }

void set_diamond2_key(byte *external_key, uint key_size, uint rounds,
    boolean invert, int block_size)
/* This procedure generates internal keys by filling the substitution box array
  s based on the external key given as input.  It DOES take a bit of time. */
  {
    uint i, j, k;
    byte *sbox;

    if (s) diamond2_done();
    numrounds = rounds;
    if (block_size == 8)
        {
        blocksize = 8;
        roundsize = 2048U;
        if (numrounds < 3)
            {
            puts("Numrounds out of range in set_diamond2_key()");
            exit(10);
            }
        }
    else if (block_size == 16)
        {
        blocksize = 16;
        roundsize = 4096U;
        if (numrounds < 5)
            {
            puts("Numrounds out of range in set_diamond2_key()");
            exit(10);
            }
        }
    else
        {
        puts("Unsupported block size in set_diamond2_key()");
        exit(11);
        }

    if ((numrounds * blocksize) > 255)
        {
        puts("Numrounds out of range in set_diamond2_key()");
        exit(10);
        }
    if (BuildCRCTable())
        {
        puts("Not enough memory.");
        exit(5);
        }
    s=(byte *) malloc(numrounds * roundsize);
    if (!s)
        {
        puts("Out of memory.");
        exit(5);
        }
    key = external_key;
    keysize = key_size;
    keyindex = 0;
    accum = 0xFFFFFFFFL;

    sbox = NULL;
    for (i = 0; i < numrounds; i++)
        {
        for (j = 0; j < blocksize; j++)
            {
            makeonebox(i, j, sbox);
    	    sbox = s + ((roundsize * i) + (256 * j));
            }
        }
    if (invert)
        {   /* Fill the inverse substitution box array si.  It is not
               necessary to do this unless the decryption mode is used.  */
        si=(byte *) malloc(numrounds * roundsize);
        if (!si)
            {
            puts("Out of memory.");
            exit(5);
            }
        for (i = 0; i < numrounds; i++)
            {
            for (j = 0; j < blocksize; j++)
                {
                for (k = 0; k < 256; k++)
                    {
                    *(si + (roundsize * i) + (256 * j) + *(s + (roundsize * i) + (256 * j) + k)) = k;
                    }
                }
            }
        }
    }

static void permute(byte *x, byte *y)   /* x and y must be different.
  This procedure is designed to make each bit of the output dependent on as
  many bytes of the input as possible, especially after repeated application.
  Each output byte takes its least significant bit from the corresponding
  input byte.  The next higher bit comes from the corresponding bit of the
  next higher input byte.  This is done until all bits of the output byte
  are filled.
*/
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

static void CALLTYPE permute_lite2(byte *a, byte *b)
  {
/* This procedure is designed to make each bit of the output dependent on as
  many bytes of the input as possible, especially after repeated application.
*/
    b[0] = (a[0] & 1) + (a[1] & 2) + (a[2] & 4) + (a[3] & 8) + (a[4] & 0x10) +
        (a[5] & 0x20) + (a[6] & 0x40) + (a[7] & 0x80);
    b[1] = (a[1] & 1) + (a[2] & 2) + (a[3] & 4) + (a[4] & 8) + (a[5] & 0x10) +
        (a[6] & 0x20) + (a[7] & 0x40) + (a[0] & 0x80);
    b[2] = (a[2] & 1) + (a[3] & 2) + (a[4] & 4) + (a[5] & 8) + (a[6] & 0x10) +
        (a[7] & 0x20) + (a[0] & 0x40) + (a[1] & 0x80);
    b[3] = (a[3] & 1) + (a[4] & 2) + (a[5] & 4) + (a[6] & 8) + (a[7] & 0x10) +
        (a[0] & 0x20) + (a[1] & 0x40) + (a[2] & 0x80);
    b[4] = (a[4] & 1) + (a[5] & 2) + (a[6] & 4) + (a[7] & 8) + (a[0] & 0x10) +
        (a[1] & 0x20) + (a[2] & 0x40) + (a[3] & 0x80);
    b[5] = (a[5] & 1) + (a[6] & 2) + (a[7] & 4) + (a[0] & 8) + (a[1] & 0x10) +
        (a[2] & 0x20) + (a[3] & 0x40) + (a[4] & 0x80);
    b[6] = (a[6] & 1) + (a[7] & 2) + (a[0] & 4) + (a[1] & 8) + (a[2] & 0x10) +
        (a[3] & 0x20) + (a[4] & 0x40) + (a[5] & 0x80);
    b[7] = (a[7] & 1) + (a[0] & 2) + (a[1] & 4) + (a[2] & 8) + (a[3] & 0x10) +
        (a[4] & 0x20) + (a[5] & 0x40) + (a[6] & 0x80);
  }

static void CALLTYPE ipermute_lite2(byte *b, byte *a)
  {
/* This is the inverse of the procedure permute. */
    a[0] = (b[0] & 1) + (b[7] & 2) + (b[6] & 4) + (b[5] & 8) + (b[4] & 0x10) +
        (b[3] & 0x20) + (b[2] & 0x40) + (b[1] & 0x80);
    a[1] = (b[1] & 1) + (b[0] & 2) + (b[7] & 4) + (b[6] & 8) + (b[5] & 0x10) +
        (b[4] & 0x20) + (b[3] & 0x40) + (b[2] & 0x80);
    a[2] = (b[2] & 1) + (b[1] & 2) + (b[0] & 4) + (b[7] & 8) + (b[6] & 0x10) +
        (b[5] & 0x20) + (b[4] & 0x40) + (b[3] & 0x80);
    a[3] = (b[3] & 1) + (b[2] & 2) + (b[1] & 4) + (b[0] & 8) + (b[7] & 0x10) +
        (b[6] & 0x20) + (b[5] & 0x40) + (b[4] & 0x80);
    a[4] = (b[4] & 1) + (b[3] & 2) + (b[2] & 4) + (b[1] & 8) + (b[0] & 0x10) +
        (b[7] & 0x20) + (b[6] & 0x40) + (b[5] & 0x80);
    a[5] = (b[5] & 1) + (b[4] & 2) + (b[3] & 4) + (b[2] & 8) + (b[1] & 0x10) +
        (b[0] & 0x20) + (b[7] & 0x40) + (b[6] & 0x80);
    a[6] = (b[6] & 1) + (b[5] & 2) + (b[4] & 4) + (b[3] & 8) + (b[2] & 0x10) +
        (b[1] & 0x20) + (b[0] & 0x40) + (b[7] & 0x80);
    a[7] = (b[7] & 1) + (b[6] & 2) + (b[5] & 4) + (b[4] & 8) + (b[3] & 0x10) +
        (b[2] & 0x20) + (b[1] & 0x40) + (b[0] & 0x80);
  }

static void substitute(uint round, byte *x, byte *y)
    {
    uint i;

    for (i = 0; i < blocksize; i++)
        y[i] = *(s + (roundsize*round) + (256*i) + x[i]);
    }

static void isubst(uint round, byte *x, byte *y)
    {
    uint i;

    for (i = 0; i < blocksize; i++)
        y[i] = *(si + (roundsize*round) + (256*i) + x[i]);
    }

void diamond2_encrypt_block(byte *x, byte *y)
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

void diamond2_decrypt_block(byte *x, byte *y)
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

void lite2_encrypt_block(byte *x, byte *y)
/* Encrypt a block of 16 bytes. */
    {
    uint round;
    byte z[16];

    substitute(0, x, y);
    for (round=1; round < numrounds; round++)
        {
        permute_lite2(y, z);
        substitute(round, z, y);
        }
    }

void lite2_decrypt_block(byte *x, byte *y)
/* Decrypt a block of 8 bytes. */
    {
    int round;
    byte z[8];
    
    isubst(numrounds-1, x, y);
    for (round=numrounds-2; round >= 0; round--)
        {
        ipermute_lite2(y, z);
        isubst(round, z, y);
        }
    }

void diamond2_done(void)
    {
    if (s)
        {
        memset(s, 0, numrounds * roundsize);
        free((char *)s);
        s=NULL;
        }
    if (si)
        {
        memset(si, 0, numrounds * roundsize);
        free((char *)si);
        si=NULL;
        }
    }

