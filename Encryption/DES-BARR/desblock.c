/*
 * A Fast software implementation of...
 *
 * the National Bureau of Standards Data Encryption Standard
 *
 * From Federal Information Processing Standards Publication 46-1, 22-Jan-88
 *
 * Written by David A. Barrett (barrett%asgard@boulder.Colorado.EDU)
 *
 * Permission is given for all purposes other than selling code based
 * upon optimizations presented here.
 */
#include <string.h>
#include "desdefs.h"			/* private data structures */

static char ident[] = 
   " @(#) desblock.c  version 1.00 23-Jan-91 by Dave Barrett\n";
static char rcsIdent[] = 
   " @(#) desblock.c  RCS: $Revision: 1.2 $ $Date: 91/02/21 00:29:08 $\n";

/*
 * The sum of all elements must be KEYBITS
 */
keyBitIndex keyRotates[STAGECOUNT] = {
   1, 1, 2, 2, 2, 2, 2, 2,
   1, 2, 2, 2, 2, 2, 2, 1,
};

/*
 * Permuted Choice 1: (PC-1)
 *
 * used only once to permute key  (64-bit to 56-bit permutation)
 * Ignores bits =   mod 8 (used as ascii parity bits)
 */
blockBitIndex keyTr1[KEYBITS] = {
   57, 49, 41, 33, 25, 17,  9,  1,
   58, 50, 42, 34, 26, 18, 10,  2,
   59, 51, 43, 35, 27, 19, 11,  3,
   60, 52, 44, 36, 			/* this missing chunk down below */
   63, 55, 47, 39, 31, 23, 15,  7, 
   62, 54, 46, 38, 30, 22, 14,  6,
   61, 53, 45, 37, 29, 21, 13,  5,
                   28, 20, 12,  4
};

#if 0
/*
 * debug 
 */
void showBits(vec, size)
   register bit *vec;
   int size;
{
   register bit *end = vec + size;
   int i;

   for (i = 0; i < size; i++) {
      printf("%d", i % 10);
   }
   putchar('\n');
   do {
      printf("%d", *vec++);
   } while (vec < end);
   putchar('\n');
}
#endif

void rotateLeft(x, size)
   bit *x;
   bitIndex  size;
{
   register bit i = x[0];

   memcpy(x, x + 1, size-1);	/* should be memove, but should work */
   x[size-1] = i;
}

void transpose(dst, src, dstSize, srcSize, perm)
   bit 	 	  *src;
   bit		  *dst;
   bitIndex 	  dstSize, srcSize;
   bitIndexVector perm;
{
   bit 	x[BLOCKBITS+BASE];
   register bit *dp = dst + dstSize;
   register bit *pp = perm + dstSize;

   memcpy(x + BASE, src, srcSize * sizeof src[0]);
   do {
      *--dp = x[*--pp];
   } while (pp > perm);
}

/*
 * Optimization 6: key2Transpose (56 to 48 bit permuted choice with packing)
 */
void key2Transpose(d, s)
   register u6  *d;
   register bit *s;
{
   register u6 i;

   i =s[13]; i<<=1; i|=s[16]; i<<=1; i|=s[10]; i<<=1; 
   i|=s[23]; i<<=1; i|=s[0];  i<<=1; i|=s[4]; 
   *d++=i; 
   i =s[2];  i<<=1; i|=s[27]; i<<=1; i|=s[14]; i<<=1; 
   i|=s[5];  i<<=1; i|=s[20]; i<<=1; i|=s[9];  
   *d++=i; 
   i =s[22]; i<<=1; i|=s[18]; i<<=1; i|=s[11]; i<<=1; 
   i|=s[3];  i<<=1; i|=s[25]; i<<=1; i|=s[7]; 
   *d++=i; 
   i =s[15]; i<<=1; i|=s[6];  i<<=1; i|=s[26]; i<<=1; 
   i|=s[19]; i<<=1; i|=s[12]; i<<=1; i|=s[1]; 
   *d++=i; 
   i =s[40]; i<<=1; i|=s[51]; i<<=1; i|=s[30]; i<<=1; 
   i|=s[36]; i<<=1; i|=s[46]; i<<=1; i|=s[54]; 
   *d++=i; 
   i =s[29]; i<<=1; i|=s[39]; i<<=1; i|=s[50]; i<<=1; 
   i|=s[44]; i<<=1; i|=s[32]; i<<=1; i|=s[47]; 
   *d++=i; 
   i =s[43]; i<<=1; i|=s[48]; i<<=1; i|=s[38]; i<<=1; 
   i|=s[55]; i<<=1; i|=s[33]; i<<=1; i|=s[52]; 
   *d++=i; 
   i =s[45]; i<<=1; i|=s[41]; i<<=1; i|=s[49]; i<<=1; 
   i|=s[35]; i<<=1; i|=s[28]; i<<=1; i|=s[31]; 
   *d=i; 
}

/* 
 * Convert a key block to a bit vector
 *
 * dst - the destination address
 * src - the source address
 */
bit *unpackKeyBlock(dst, src)
   register bit *dst;
   register u8  *src;
{
   register u8   b;
   register unsigned c0;
   register unsigned c1;

   c1 = 8;
   dst -= 8;				/* new */
   do {
      dst += 16;			/* new */
      b    = *src++;
      c0   = 8;
      do {
	 *--dst = b & 1;		/* was *dst++ */
	 b >>= 1;
      } while (--c0 != 0);
   } while (--c1 != 0);
   return dst + 8;
}

/*
 * Given a key string, produce a key suitable for encryption, decryption
 *
 * On input, key must be initialized to 0 or a pointer to adequate storage
 *
 * Set decr to 1 for decryption, 0 for encryption
 */
void desMakeKey(key, keyBits, keysize, decr)
   desKeyType    **key;
   u8            *keyBits;
   unsigned      keysize;
   int           decr;
{
   desUnion   keyBlock;
   bit        key64[BLOCKBITS];
   bit        key56[KEYBITS];
   stageRange stage;
   int        j;

   if (*key == (desKeyType *) 0) {
      *key = (desKeyType *) malloc(sizeof (desKeyType));
      if (*key == (desKeyType *) 0) return;
   }

   (*key)->decr = decr;
   if (keysize >= DES_BLOCKSIZE) {
      memcpy((void *) &keyBlock, (void *) keyBits, DES_BLOCKSIZE);
   } else {
      memcpy(keyBlock.bytes, keyBits, keysize);
      memset(keyBlock.bytes + keysize, 0, DES_BLOCKSIZE - keysize);
   }
   unpackKeyBlock(key64, keyBlock.bytes);
   transpose(key56, key64, KEYBITS, BLOCKBITS, keyTr1);	/* 64->56 bits */

   for (stage = 0; stage < STAGECOUNT; stage++) {
      for (j = 0; j < keyRotates[stage]; j++) {
	 rotateLeft(key56, KEYBITS/2);
	 rotateLeft(key56 + KEYBITS/2, KEYBITS/2);
      }
      key2Transpose(&((*key)->bits[!decr ? STAGECOUNT-1-stage : stage]), key56);
   }
}

/*
 * Return the size of an input block
 */
int desInBlockSize(key)
   desKeyType *key;
{
   return DES_BLOCKSIZE;
}

/*
 * Return the size of an output block
 */
int desOutBlockSize(key)
   desKeyType *key;
{
   return DES_BLOCKSIZE;
}

/* 
 * Convert a desPair to a string of bytes
 */
void desUnpackBlock(dst, src)
   u8 		*dst;
   desPair     	*src;
{
   register u8  *dp = dst + 8;
   register u32 s;

   s = src->right;
   *--dp = (u8) s; s >>= 8;
   *--dp = (u8) s; s >>= 8;
   *--dp = (u8) s; s >>= 8;
   *--dp = s;

   s = src->left;
   *--dp = (u8) s; s >>= 8;
   *--dp = (u8) s; s >>= 8;
   *--dp = (u8) s; s >>= 8;
   *--dp = s;
}

/* 
 * Convert a string of bytes to a desPair
 */
void desPackBlock(dst, src)
   desPair      *dst;
   u8      	*src;
{
   register u32  d;
   register u8   *sp = src;

   d  = *sp++; d<<= 8;
   d |= *sp++; d<<= 8;
   d |= *sp++; d<<= 8;
   d |= *sp++;
   dst->left = d;
   d  = *sp++; d<<= 8;
   d |= *sp++; d<<= 8;
   d |= *sp++; d<<= 8;
   d |= *sp++;
   dst->right = d;
}

/*
 * Optimization 13:
 *
 * Lots of instructions, but relatively fast.
 *
 * 4 each for a total of 259 instructions (64 are memory fetches)
 */
void IP(d, s)
   desPair *d, *s;
{
   register u32 l = s->left;
   register u32 r = s->right;
   register u32 i, j, k;

   i = 0; 			  j = 0;
   i	|=l&((u32)1<<10); k=l<<2; j	|=k&0x2000008;    k<<=1;
   i	|=k&0x2000008;    k<<=2;  j	|=k&((u32)1<<18); k<<=1;
   i	|=k&((u32)1<<18); k<<=2;  j	|=k&((u32)1<<11); k<<=1;
   i	|=k&((u32)1<<11); k<<=2;  j	|=k&((u32)1<<26); k<<=1;
   i	|=k&((u32)1<<26); k<<=2;  j	|=k&((u32)1<<19); k<<=1;
   i	|=k&((u32)1<<19); k<<=5;  j	|=k&((u32)1<<27); k<<=1;
   i	|=k&((u32)1<<27); k=l>>1; j	|=k&((u32)1<<10); k>>=2;
   i	|=k&((u32)1<<17); k>>=1;  j	|=k&((u32)1<<17); k>>=2;
   i	|=k&0x1000004;    k>>=1;  j	|=k&0x1000004;    k>>=2;
   i	|=k&((u32)1<<9);  k>>=1;  j	|=k&((u32)1<<9);  k>>=2;
   i	|=k&((u32)1<<16); k>>=1;  j	|=k&((u32)1<<16); k>>=2;
   i	|=k&((u32)1<<1);  k>>=1;  j	|=k&((u32)1<<1);  k>>=2;
   i	|=k&((u32)1<<8);  k>>=1;  j	|=k&((u32)1<<8);  k>>=5;
   i	|=k&1; 	 	  k>>=1;  j	|=k&1;
   				  j	|=r&((u32)1<<21); k=r<<1;
   i	|=k&((u32)1<<21); k<<=2;  j	|=k&((u32)1<<14); k<<=1;
   i	|=k&((u32)1<<14); k<<=2;  j	|=k&0x20000080;   k<<=1;
   i	|=k&0x20000080;   k<<=2;  j	|=k&((u32)1<<22); k<<=1;
   i	|=k&((u32)1<<22); k<<=2;  j	|=k&((u32)1<<15); k<<=1;
   i	|=k&((u32)1<<15); k<<=2;  j	|=k&((u32)1<<30); k<<=1;
   i	|=k&((u32)1<<30); k<<=2;  j	|=k&((u32)1<<23); k<<=1;
   i	|=k&((u32)1<<23); k<<=5;  j	|=k&((u32)1<<31); k<<=1;
   i	|=k&((u32)1<<31); k=r>>2; 
   i	|=k&0x10000040;   k>>=1;  j	|=k&0x10000040;   k>>=2;
   i	|=k&((u32)1<<13); k>>=1;  j	|=k&((u32)1<<13); k>>=2;
   i	|=k&((u32)1<<20); k>>=1;  j	|=k&((u32)1<<20); k>>=2;
   i	|=k&((u32)1<<5);  k>>=1;  j	|=k&((u32)1<<5);  k>>=2;
   i	|=k&((u32)1<<12); k>>=1;  j	|=k&((u32)1<<12); k>>=5;
   i	|=k&((u32)1<<4);  k>>=1;  j	|=k&((u32)1<<4);

   d->left  = i;		  d->right = j;
}

/*
 * Optimization 8: IP inverse = swapTr combined with finalTr 
 * Optimization 9: add l,r;
 * Optimization 13: use packed bits for l and r
 * Optimization 14: packed to packed
 *
 * 259 Instructions (64 are memory stores)
 */
void IPinverse(d, l, r)
   desPair  *d;
   register u32 l, r;
{
   register u32 i;

   i =l<<7&((u32)1<<31);  i|=r<<6&((u32)1<<30);
   i|=l<<13&((u32)1<<29); i|=r<<12&((u32)1<<28);
   i|=l<<19&((u32)1<<27); i|=r<<18&((u32)1<<26);
   i|=l<<25&((u32)1<<25); i|=r<<24&((u32)1<<24);
   i|=l>>2&((u32)1<<23);  i|=r>>3&((u32)1<<22);
   i|=l<<4&((u32)1<<21);  i|=r<<3&((u32)1<<20);
   i|=l<<10&((u32)1<<19); i|=r<<9&((u32)1<<18);
   i|=l<<16&((u32)1<<17); i|=r<<15&((u32)1<<16);
   i|=l>>11&((u32)1<<15); i|=r>>12&((u32)1<<14); 
   i|=l>>5&((u32)1<<13);  i|=r>>6&((u32)1<<12);
   i|=l<<1&((u32)1<<11);  i|=r<<0&((u32)1<<10); 
   i|=l<<7&((u32)1<<9);   i|=r<<6&((u32)1<<8);
   i|=l>>20&((u32)1<<7);  i|=r>>21&((u32)1<<6);
   i|=l>>14&((u32)1<<5);  i|=r>>15&((u32)1<<4);
   i|=l>>8&((u32)1<<3);   i|=r>>9&((u32)1<<2); 
   i|=l>>2&((u32)1<<1);   i|=r>>3&((u32)1<<0);
   d->left = i;
   i =l<<3&((u32)1<<31);  i|=r<<2&((u32)1<<30);
   i|=l<<9&((u32)1<<29);  i|=r<<8&((u32)1<<28);
   i|=l<<15&((u32)1<<27); i|=r<<14&((u32)1<<26);
   i|=l<<21&((u32)1<<25); i|=r<<20&((u32)1<<24);
   i|=l>>6&((u32)1<<23);  i|=r>>7&((u32)1<<22); 
   i|=l<<0&((u32)1<<21);  i|=r>>1&((u32)1<<20);
   i|=l<<6&((u32)1<<19);  i|=r<<5&((u32)1<<18); 
   i|=l<<12&((u32)1<<17); i|=r<<11&((u32)1<<16);
   i|=l>>15&((u32)1<<15); i|=r>>16&((u32)1<<14); 
   i|=l>>9&((u32)1<<13);  i|=r>>10&((u32)1<<12); 
   i|=l>>3&((u32)1<<11);  i|=r>>4&((u32)1<<10);
   i|=l<<3&((u32)1<<9);   i|=r<<2&((u32)1<<8);
   i|=l>>24&((u32)1<<7);  i|=r>>25&((u32)1<<6);
   i|=l>>18&((u32)1<<5);  i|=r>>19&((u32)1<<4);
   i|=l>>12&((u32)1<<3);  i|=r>>13&((u32)1<<2); 
   i|=l>>6&((u32)1<<1);   i|=r>>7&((u32)1<<0);
   d->right = i;
}

/*
 * This function accounts for at least 60% of execution time
 */
u32 desFunc(inp, key)
   u32 		inp;
   u6Block     	key;
{
   register u32	 p, r, q;

   p   = inp; p >>= 27;
   q   = p;   q  &= 3;  q <<= 4;
   r   = inp; r <<= 5;
   p  |= r;
   r  = sBoxp[0][key[0] ^ (p & 63)]; p >>= 4;
   r |= sBoxp[7][key[7] ^ (p & 63)]; p >>= 4;
   r |= sBoxp[6][key[6] ^ (p & 63)]; p >>= 4;
   r |= sBoxp[5][key[5] ^ (p & 63)]; p >>= 4;
   r |= sBoxp[4][key[4] ^ (p & 63)]; p >>= 4;
   r |= sBoxp[3][key[3] ^ (p & 63)]; p >>= 4;
   r |= sBoxp[2][key[2] ^ (p & 63)]; p >>= 4;
   r |= sBoxp[1][key[1] ^ (p | q)];

   return r;
}

void des(dst, src, key)
   u8          *dst;
   u8	       *src;
   desKeyType  *key;
{
   desPair	dblock, sblock;
   stageRange  	stage = STAGECOUNT;
   register u32	left, right, res;
   desPair  	temp;

   desPackBlock(&sblock, src);
   IP(&temp, &sblock);
   left  = temp.left;
   right = temp.right;

   do {
      res   = desFunc(right, key->bits[--stage]);
      res  ^= left;
      left  = right;
      right = res;
   } while (stage != 0);

   IPinverse(&dblock, left, right);
   desUnpackBlock(dst, &dblock);
}
