/* No representations are made concerning either the merchantability of
   this software or the suitability of this software for any particular
   purpose. It is provided "as is" without express or implied warranty
   of any kind.  
                                                                    
   License to copy and use this software is granted provided that these
   notices are retained in any copies of any part of this documentation
   and/or software.  
 */

#include <string.h>
#include <ctype.h>
#include "hexbinpr.h"

/*--- function HexToBin ---------------------------------------------------
 *
 *  Converts a string of (an even number of) hex digits to binary.
 *
 *  Entry    hex      is a string of hex characters, upper or lower case.
 *                    Spaces are to be ignored.
 *                    Conversion stops at the first non-space that
 *                    is a non-hex digit.
 *           maxbytes is the amount of space set aside in "bin".
 *
 *  Exit     bin    is an array of binary bytes.
 *           Returns the number of bytes converted if successful, else 0
 *              (if the number of hex digits is odd).
 */
int
HexToBin(hex,maxbytes,bin)
char *hex;
int maxbytes;
unsigned char *bin;
{
  char ch, upper=1;
  unsigned char val;
  int nbytes = 0;
  

  for(; nbytes<maxbytes; hex++) {
    ch = *hex;
    if(ch == ' ') continue;
    if(islower(ch)) ch = (char)toupper(ch);
    if(isdigit(ch)) {
      val = (unsigned char) (ch - '0');
    } else if(ch>='A' && ch<='F') {
      val = (unsigned char)(ch - 'A' + 10);
      
      /* End of hex digits--time to bail out.
       */
    } else {
      return (upper ? nbytes : 0);
    }
    
    /* If this is an upper digit, set the top 4 bits of the destination
     * byte with this value, else -OR- in the value.
     */
    if(upper) {
      *bin = (unsigned char) (val << 4);
      upper = 0;
    } else {
      *(bin++) |= val;
      upper = 1;
      nbytes++;  /* Increment only after byte has been filled. */
    }
  }
  return (nbytes);
}


/*--- function BinToHex --------------------------------------------------
 *
 *  Convert an array of bytes to hexadecimal.
 *
 *  Entry   bin      is an array of bytes.
 *          nbytes   is the number of bytes in the array.
 *
 *  Exit    hex      is a string of hexadecimal digits, zero-terminated.
 */
void
BinToHex(bin,nbytes,hex)
unsigned char *bin;
int nbytes;
char *hex;
{
#define btoh(byte) (byte<10 ? byte+'0' : byte-10+'A')

  unsigned char byte;

  while(nbytes--) {
    byte = (unsigned char)((*(bin)>>4) & 0xf);
    *(hex++) = (char) btoh(byte);
    byte = (unsigned char) (*(bin++) & 0xf);
    *(hex++) = (char) btoh(byte);
  }
  *hex = '\0';
}
