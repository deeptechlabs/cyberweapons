#include <string.h>
#include "des.h"

/*
 * Data Encryption Standard: 64-bit cipher-feedback mode encryption/decryption
 *
 * Note:  destination and source may overlap for encryption but not decryption
 *
 * To create a message authentication code (MAC):
 * The returned iv from the final call to either CFB routine should be 
 * passed to the DES function.  The leftmost (most significant) n-bits may 
 * be used as the MAC.  Deciphering the ciphertext will produce the same
 * MAC as enciphering the plaintext.  This is the method used in FIPS
 * Pub 81, with 64-bit CFB mode, with the last block shifted in by the
 * number of bits it contains.
 *
 * If compatability with FIPS Publication 113 is desired, the input data
 * should be padded with zeros until it is a multiple of 8 bytes.  Then, the
 * iv should be set to the first eight bytes of the input data, and the
 * remaining bytes enciphered (or ciphertext deciphered).  Then use the
 * final iv as above.  
 *
 * Written by: David A. Barrett (barrett%asgard@boulder.Colorado.EDU)
 */
void desXor(d, s, x, count)
   register char *d, *s, *x;
   register unsigned count;
{
   if (count != 0) do {
      *d++ = *s++ ^ *x++;
   } while (--count != 0);
}

/*
 * Encipher/decipher a block of memory using cipher-feedback mode
 *
 * Input:
 *    dst, src, size = destination and source addresses and their size in bytes
 *    iv     = initialization vector  (right-justified 0 padded on 1st call)
 *    ivsize =  number of bytes in iv (should be DES_BLOCKSIZE on 1st call)
 *    decr   =  non-zero for decryption, zero for encryption
 *
 * Output:
 *    iv     = the next initialization vector
 *    ivsize = The size of the next initialization vector
 */
unsigned desCFB(dst, src, size, iv, ivsize, key, decr)
   register char     *dst, *src, *iv;
   register unsigned size, ivsize; 
   keyType 	     key;
   int		     decr;
{
   register char *inp = dst;

   if (decr) inp = src; 

   if (ivsize != DES_BLOCKSIZE) {
      if (size < ivsize) {
	 desXor(dst, iv, src, size);
	 memcpy(iv, iv + size, DES_BLOCKSIZE - size);
	 memcpy(iv + DES_BLOCKSIZE - size, inp, size);
	 return ivsize - size;
      }
      desXor(dst, iv, src, ivsize);
      memcpy(iv, iv + ivsize, DES_BLOCKSIZE - ivsize);
      memcpy(iv + DES_BLOCKSIZE - ivsize, inp, ivsize);
      dst  += ivsize;
      src  += ivsize;
      inp  += ivsize;
      size -= ivsize;
   }

   if (size != 0) {
      des(iv, iv, key);
   }
   if (size > DES_BLOCKSIZE) do {
      desXor(dst, iv, src, DES_BLOCKSIZE);
      des(iv, inp, key);
      dst  += DES_BLOCKSIZE;
      src  += DES_BLOCKSIZE;
      inp  += DES_BLOCKSIZE;
      size -= DES_BLOCKSIZE;
   } while (size > DES_BLOCKSIZE);

   ivsize = DES_BLOCKSIZE - size;

   desXor(dst, iv, src, size);
   memcpy(iv, iv + size, ivsize);		/* shift DES left */
   memcpy(iv + ivsize, inp, size);		/* shift in input */

   return ivsize;
}
