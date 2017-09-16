/*
 * String to key transformation based upon:
 *
 *    FIPS Pub 112: "Password Usage" 1985 May 30.
 *
 * Written by David A. Barrett	(barrett@boulder.Colorado.EDU)
 */
#include "des.h"
#include "string.h"

/*
 * Compute a Message Authentication code according to 
 *    FIPS Pub 113: "Computer Data Authentication" 1985 May 30
 * 
 * Uses DES in CBC mode with IV = 0, input string padded on right with <pad> 
 * to positive multiple of DES_BLOCKSIZE bytes.
 *    set pad = '\0' for FIPS Pub 113.
 *    set pad = ' '  for FIPS Pub 112.
 */
void desStrMAC(mac, src, len, pad, key)
   register char *mac, *src;
   register unsigned len;
   char pad;
   keyType key;
{
   char buf[DES_BLOCKSIZE];

   memset(mac, '\0', DES_BLOCKSIZE);			/* IV */

   if (len > DES_BLOCKSIZE) do {
      desXor(mac, mac, src, DES_BLOCKSIZE);
      des(mac, mac, key);
      src += DES_BLOCKSIZE;
      len -= DES_BLOCKSIZE;
   } while (len > DES_BLOCKSIZE);

   memcpy(buf, src, len);	/* len can be 0 or DES_BLOCKSIZE */
   memset(buf + len, pad, DES_BLOCKSIZE - len);
   desXor(mac, mac, buf, DES_BLOCKSIZE);
   des(mac, mac, key);
}

/*
 * Shift each byte in a block of memory left by one bit
 *
 * Used because ASCII has high bit clear, and DES ignores low bit.
 */
void setkeybits(d, s, count)
   register char *d, *s;
   register unsigned count;
{
   if (count != 0) do {
      *d++ = *s++ << 1;			/* ignore hi bit, clear lo bit */
   }  while (--count != 0);
}

/*
 * Convert an ASCII string of arbitrary length to an 8-byte key suitable as an 
 * input key for the DES.
 *
 * The string is padded on the right with <pad> to a multiple of 8 characters.
 * The minimim length of the resulting string will be 16 characters.
 * A key is computed by using the first 8 characters of the string, each
 * character left-shifted by one bit.  This key is used to encipher the
 * remaining characters of the string using the DES in CFB mode, IV = 0,
 * to compute a Message Authentication Code ala FIPS PUB 113.
 *
 * For input strings of 8 or fewer characters, this will result in the
 * DES encryption of the string consisting of 8 <pad> characters.  FIPS
 * Pub 112 used the space character for <pad>.
 *
 * Note: Unlike fips Pub 112, this algorithm does not restrict the output
 * bits to be an 8 character string consisting of the printable ASCII
 * characters.  The string is returned as 8 chararcters of 8-bits each.
 * No parity is computed.
 */
void desKey(keybits, str, pad)
   char *keybits;
   char *str;
   int pad;
{
   register unsigned len = strlen(str);
   unsigned     keysize = len;
   keyType 	key = (keyType) 0;

   if (keysize > DES_BLOCKSIZE) keysize = DES_BLOCKSIZE;

   setkeybits(keybits, str, keysize);		/* key */
   memset(keybits + keysize, pad << 1, DES_BLOCKSIZE - keysize);
   str += keysize;
   len -= keysize;

   desMakeKey(&key, keybits, DES_BLOCKSIZE, 0);		/* encryption mode */
   desStrMAC(keybits, str, len, pad, key);
   free(key);
}
