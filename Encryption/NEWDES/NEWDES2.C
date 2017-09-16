/*--- newdes2.c -- Program to implement the NEWDES algorithm.
 *
 *   See Robert Scott's article "Wide-open Encryption Design Offers
 *   Flexible Implementations" in Volume 9, Number 1 (January 1985)
 *   of Cryptologia.
 *   This algorithm resembles the Data Encryption Standard, but is easier
 *   to implement in software and is supposed to be more secure.
 *
 *   Based on my March 1988 8086 assembly language version.
 *
 *   Mark Riordan    12 August 1990.
 */
#include "newdes2p.h"

#define SIZE_ROTOR	 256
#define SIZE_KEY_UNRAV	 60
#define SIZE_USER_KEY	 15
#define BLOCK_BYTES	 8

#if 0
unsigned int newdes_buf(unsigned char *buf,unsigned int block_length);
void newdes_block(unsigned char *block);
void newdes_set_key_encipher(unsigned char *key);
void newdes_set_key_decipher(unsigned char *key);
#endif

unsigned char newdes_rotor[SIZE_ROTOR]
 = {
    32,137,239,188,102,125,221, 72,212, 68, 81, 37, 86,237,147,149,
    70,229, 17,124,115,207, 33, 20,122,143, 25,215, 51,183,138,142,
   146,211,110,173,  1,228,189, 14,103, 78,162, 36,253,167,116,255,
   158, 45,185, 50, 98,168,250,235, 54,141,195,247,240, 63,148,  2,
   224,169,214,180, 62, 22,117,108, 19,172,161,159,160, 47, 43,171,
   194,175,178, 56,196,112, 23,220, 89, 21,164,130,157,  8, 85,251,
   216, 44, 94,179,226, 38, 90,119, 40,202, 34,206, 35, 69,231,246,
    29,109, 74, 71,176,  6, 60,145, 65, 13, 77,151, 12,127, 95,199,
    57,101,  5,232,150,210,129, 24,181, 10,121,187, 48,193,139,252,
   219, 64, 88,233, 96,128, 80, 53,191,144,218, 11,106,132,155,104,
    91,136, 31, 42,243, 66,126,135, 30, 26, 87,186,182,154,242,123,
    82,166,208, 39,152,190,113,205,114,105,225, 84, 73,163, 99,111,
   204, 61,200,217,170, 15,198, 28,192,254,134,234,222,  7,236,248,
   201, 41,177,156, 92,131, 67,249,245,184,203,  9,241,  0, 27, 46,
   133,174, 75, 18, 93,209,100,120, 76,213, 16, 83,  4,107,140, 52,
    58, 55,  3,244, 97,197,238,227,118, 49, 79,230,223,165,153, 59
};

unsigned char newdes_key_unravelled[SIZE_KEY_UNRAV];


/*--- function newdes_buf -------------------------------------------
 *
 * Encipher or decipher a buffer of data.
 *
 *    Entry    buf	      points to the buffer.
 *	       block_length   is the number of bytes in the buffer.
 *			      If it is not a multiple of 8, it will be
 *			      rounded up to the next multiple of 8--
 *			      so make sure that the buffer is long enough.
 *	       newdes_key_unravelled   points to the key.  It has
 *			been "unravelled" as necessary for either
 *			enciphering or deciphering.
 *	       newdes_rotor   is the fundamental mapping function
 *			      (array) for NEWDES.
 *
 *    Exit     Returns the number of bytes now in the buffer
 *		 (rounded up as described above).
 */
unsigned int
newdes_buf(buf,block_length)
unsigned char *buf;
unsigned int block_length;
{
   unsigned int mylen, mylen2;

   if(block_length > 0) {
      mylen2 = mylen = (((block_length - 1) / BLOCK_BYTES) + 1) * BLOCK_BYTES;
   }

   for(;mylen; mylen -= BLOCK_BYTES){
      newdes_block(buf);
      buf += BLOCK_BYTES;
   }

   return(mylen2);
}

/*--- function newdes_block -----------------------------------------
 *
 *  Encipher or decipher an 8-byte block.
 *
 *    Entry    block	points to the block.
 *	       newdes_key_unravelled   points to the key.  It has
 *			been "unravelled" as necessary for either
 *			enciphering or deciphering.
 *	       newdes_rotor   is the fundamental mapping function
 *			      (array) for NEWDES.
 */
void
newdes_block(block)
unsigned char *block;
{
   unsigned char *keyptr = newdes_key_unravelled;
   register unsigned char *byteptr = block;
   int count;

#define B0 (*byteptr)
#define B1 (*(byteptr+1))
#define B2 (*(byteptr+2))
#define B3 (*(byteptr+3))
#define B4 (*(byteptr+4))
#define B5 (*(byteptr+5))
#define B6 (*(byteptr+6))
#define B7 (*(byteptr+7))

   for(count=8; count--;) {
      B4 = B4 ^ newdes_rotor[B0 ^ *(keyptr++)];
      B5 = B5 ^ newdes_rotor[B1 ^ *(keyptr++)];
      B6 = B6 ^ newdes_rotor[B2 ^ *(keyptr++)];
      B7 = B7 ^ newdes_rotor[B3 ^ *(keyptr++)];

      B1 = B1 ^ newdes_rotor[B4 ^ *(keyptr++)];
      B2 = B2 ^ newdes_rotor[B4 ^ B5];
      B3 = B3 ^ newdes_rotor[B6 ^ *(keyptr++)];
      B0 = B0 ^ newdes_rotor[B7 ^ *(keyptr++)];
   }
   B4 = B4 ^ newdes_rotor[B0 ^ *(keyptr++)];
   B5 = B5 ^ newdes_rotor[B1 ^ *(keyptr++)];
   B6 = B6 ^ newdes_rotor[B2 ^ *(keyptr++)];
   B7 = B7 ^ newdes_rotor[B3 ^ *(keyptr++)];
}

/*--- function newdes_set_key_encipher ---------------------------------
 *
 *    Set newdes to encipher using a given key.
 *
 *    Entry    key   points to a 15-byte key.
 *
 *    Exit     newdes_key_unravelled   contains the key set up properly
 *		     for use in newdes_block, for enciphering.
 */
void
newdes_set_key_encipher(key)
unsigned char *key;
{
   unsigned char *kuserptr, *kunravptr;
   int outloopct = SIZE_KEY_UNRAV / SIZE_USER_KEY;
   int inloopct;

   kunravptr = newdes_key_unravelled;
   for(;outloopct--;) {
      kuserptr = key;
      for(inloopct=SIZE_USER_KEY; inloopct--;) {
	 *(kunravptr++) = *(kuserptr++);
      }
   }
}


/*--- function newdes_set_key_decipher ---------------------------------
 *
 *    Set newdes to decipher using a given key.
 *
 *    Entry    key   points to a 15-byte key.
 *
 *    Exit     newdes_key_unravelled   contains the key set up properly
 *		     for use in newdes_block, for deciphering.
 */
void
newdes_set_key_decipher(key)
unsigned char *key;
{
   unsigned char *kunravptr;
   int outloopct = SIZE_KEY_UNRAV / SIZE_USER_KEY;
   int userkeyidx;

   kunravptr = newdes_key_unravelled;
   userkeyidx = 11;
   while (1) {
      *(kunravptr++) = key[userkeyidx];
      userkeyidx++;
      if(userkeyidx == SIZE_USER_KEY) userkeyidx = 0;

      *(kunravptr++) = key[userkeyidx];
      userkeyidx++;
      if(userkeyidx == SIZE_USER_KEY) userkeyidx = 0;

      *(kunravptr++) = key[userkeyidx];
      userkeyidx++;
      if(userkeyidx == SIZE_USER_KEY) userkeyidx = 0;

      *(kunravptr++) = key[userkeyidx];
      userkeyidx = (userkeyidx+9) % 15;

      if(userkeyidx == 12) break;

      *(kunravptr++) = key[userkeyidx++];
      *(kunravptr++) = key[userkeyidx++];

      *(kunravptr++) = key[userkeyidx];

      userkeyidx = (userkeyidx+9) % 15;
   }
}
