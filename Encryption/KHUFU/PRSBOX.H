/* @(#)prsbox.h	4.1 7/13/89 14:44:19 */
/*
 * prsbox.h - header file for prsbox
 *
 * Landon Curt Noll makes no representations concerning either the
 * merchantability of this software or the suitability of this software for
 * any particular purpose.  It is provided "as is" without express or 
 * implied warranty of any kind.
 *
 * This file has been put in the public domain.  Please leave it that way.
 *
 * By: Landon Curt Noll   (chongo@toad.com  -or  uunet!hoptoad!chongo)
 */

/* 
 * sbox typedefs
 *
 * The u32bit typedef must be a 32 bit value, no more, no less, and
 * must be unsigned.  The sbox typedef must be an array of 256 (one
 * for each possible byte value) u32bit values.
 */
typedef unsigned long u32bit;
typedef u32bit sbox[256];

/*
 * size macros
 */
#define MAX_SBOX_COUNT 8			 /* S boxes in a set */
#define SBOX_WORDS (sizeof(sbox)/sizeof(u32bit)) /* S box u32bit length */

/*
 * ROTATE - rotate a value as unsigned 32 bit value by table lookup
 *
 * Rotate a 4 byte chunk `val' right by `count' bits.  
 * The chucnk `val' will be cast into an unsigned 32 bit value.
 * The result will be an unsigned 32 bit value.
 */
#define ROTATE(val, count) \
    (((u32bit)(val))<<(32-(count)) | ((u32bit)(val))>>(count))

/*
 * SWAP - swap the ENDIAN order
 */
#define SWAP(x) \
    ( (((x)&0xff)<<24) | (((x)&0xff00)<<8) | \
      (((x)&0xff0000)>>8) | (((x)&0xff000000)>>24) )
