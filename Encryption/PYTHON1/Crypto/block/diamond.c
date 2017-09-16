
/*
 *  diamond.c : Implementation of the Diamond block encryption algorithm
 *
 * Part of the Python Cryptography Toolkit, version 1.0.0
 *
 * Copyright (C) 1995, A.M. Kuchling
 *
 * Distribute and use freely; there are no restrictions on further 
 * dissemination and usage except those imposed by the laws of your 
 * country of residence.
 *
 */
  

#define MAX_NUM_ROUNDS 16

typedef struct 
{
 PCTObject_HEAD
  unsigned char s[4096*MAX_NUM_ROUNDS], si[4096*MAX_NUM_ROUNDS]; 
  int keyindex, num_rounds;
  unsigned long accum;
} Diamondobject;


/* Make sure that the following macro is called after BuildCRCTable() but
   before crc32done(). */

#define crc32(crc, c)(((crc>>8)&0x00FFFFFFL)^(Ccitt32Table[(unsigned int)((unsigned int)crc^c)&0xFF]))

/* crc.cpp -- contains table based CCITT 32 bit CRC function.
   This file is in the Public Domain.
   */

#define CRC_MASK           0xFFFFFFFFL
#define CRC32_POLYNOMIAL   0xEDB88320L

static unsigned int Ccitt32Table[256];

/****************************************************************************/

/*
 * This routine simply builds the coefficient table used to calculate
 * 32 bit CRC values throughout this program.  The 256 long word table
 * has to be set up once when the program starts.  Alternatively, the
 * values could be hard coded in, which would offer a miniscule improvement
 * in overall performance of the program.
 */

int  BuildCRCTable()
{
  int i;
  int j;
  unsigned int value;

  for ( i = 0; i <= 255 ; i++ )
    {
      value = i;
      for ( j = 8 ; j > 0; j-- )
	{
	  if ( value & 1 )
	    value = ( value >> 1 ) ^ CRC32_POLYNOMIAL;
	  else
	    value >>= 1;
	}
      Ccitt32Table[ i ] = value;
    }
  return 0;
}


/* diamond.c - Encryption designed to exceed DES in security.
   This file and the Diamond and Diamond Lite Encryption Algorithms
   described herein are hereby dedicated to the Public Domain by the
   author and inventor, Michael Paul Johnson.  Feel free to use these
   for any purpose that is legally and morally right.  The names
   "Diamond Encryption Algorithm" and "Diamond Lite Encryption
    Algorithm" should only be used to describe the algorithms described
    in this file, to avoid confusion.
    
    Disclaimers:  the following comes with no warranty, expressed or
    implied.  You, the user, must determine the suitability of this
    information to your own uses.  You must also find out what legal
    requirements exist with respect to this data and programs using
    it, and comply with whatever valid requirements exist.
    */

int inline keyrand(self, max_value, key, keysize)
     Diamondobject *self;
     int max_value;
     unsigned char *key;
     int keysize;
{				/* value based on key[], sized keysize */
  int prandvalue, i;
  unsigned long mask;

  if (!max_value) return 0;
  mask = 0L;			/* Create a mask to get the minimum */
  for (i=max_value; i > 0; i = i >> 1) /* number of bits to cover the */
    mask = (mask << 1) | 1L;	/* range 0 to max_value. */
  i=0;
  do
    {
      self->accum = crc32(self->accum, key[self->keyindex++]);
      if (self->keyindex >= keysize)
	{
	  self->keyindex = 0;		/* Recycle thru the key */
	  self->accum = crc32(self->accum, (keysize & 0xFF));
	  self->accum = crc32(self->accum, ((keysize >> 8) & 0xFF));
	}
      prandvalue = (int) (self->accum & mask);
      if ((++i>97) && (prandvalue > max_value))	/* Don't loop forever. */
	prandvalue -= max_value; /* Introduce negligible bias. */
    }
  while (prandvalue > max_value); /* Discard out of range values. */
  return prandvalue;
}

static void inline makeonebox(self, i, j, key, keylen)
     Diamondobject *self;
     int i, j;
     unsigned char *key;
     int keylen;
{
  int n;
  int pos, m, p;
  int filled[256];
  
  for (m = 0; m < 256; m++)	/* The filled array is used to make
				   sure that */
    filled[m] = 0;		/* each byte of the array is filled only once. */
  for (n = 255; n >= 0 ; n--)	/* n counts the number of bytes left to fill */
    {
      pos = keyrand(self, n, key, keylen);		/* pos is the position among the UNFILLED */
      /* components of the s array that the */
      /* number n should be placed.  */
      p=0;
      while (filled[p]) p++;
      for (m=0; m<pos; m++)
	{
	  p++;
	  while (filled[p]) p++;
	}
      self->s[(4096*i) + (256*j) + p] = n;
      filled[p] = 1;
    }
}

static inline void Diamondinit(self, key, keylen)
     Diamondobject *self;
     unsigned char *key;
     int keylen;
{
  int i, j, k;
  BuildCRCTable();
  self->keyindex = 0;
  self->accum = 0xFFFFFFFFL;

  if (key[0]<5 || MAX_NUM_ROUNDS<=key[0]) 
    {
      PyErr_SetString(PyExc_ValueError, "Number of rounds for Diamond must be "
		    "between 5 and 15.");
      return;
    }
  self->num_rounds=key[0];
  key++; keylen--;
  for (i = 0; i < self->num_rounds; i++)
    {
      for (j = 0; j < 16; j++)
	{
	  makeonebox(self, i, j, key, keylen);
	}
    }
  for (i = 0; i < self->num_rounds; i++)
    {
      for (j = 0; j < 16; j++)
	{
	  for (k = 0; k < 256; k++)
	    {
	      self->si[(4096 * i) + (256 * j) + self->s[(4096 * i) + (256 * j) + k]] = k;
	    }
	}
    }
}

static void permute(self, x, y)   /* x and y must be different. */
     Diamondobject *self;
     unsigned char *x, *y;
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

static void ipermute(self, x, y) /* x!=y */
     Diamondobject *self;
     unsigned char *x, *y;
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

static void inline substitute(self, round, x, y)
     Diamondobject *self;
     int round;
     unsigned char *x, *y;
{
  int i;
  
  for (i = 0; i < 16; i++)
    y[i] = self->s[(4096*round) + (256*i) + x[i]];
}

static void inline isubst(self, round, x, y)
     Diamondobject *self;
     int round;
     unsigned char *x, *y;
{
  int i;
  
  for (i = 0; i < 16; i++)
    y[i] = self->si[(4096*round) + (256*i) + x[i]];
}

 void Diamondencrypt(self, block)
      Diamondobject *self;
      unsigned char *block;
 {
   int round;
   unsigned char y[16], z[16];

   substitute(self, 0, block, y);
   for (round=1; round < self->num_rounds; round++)
     {
       permute(self, y, z);
       substitute(self, round, z, y);
     }
   for(round=0; round<16; round++) block[round]=y[round];
 }

 void Diamonddecrypt(self, block)
      Diamondobject *self;
      unsigned char *block;
 {
   int round;
   unsigned char y[16], z[16];

   isubst(self, self->num_rounds-1, block, y);
   for (round=self->num_rounds-2; round >= 0; round--)
     {
       ipermute(self, y, z);
       isubst(self, round, z, y);
     }
   for(round=0; round<16; round++) block[round]=y[round];
 }



