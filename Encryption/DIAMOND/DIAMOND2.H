/* diamond2.h -- program interface to the Diamond2 and Diamond2 Lite Block
   Ciphers.  This file dedicated to the Public Domain by Mike Johnson, the 
   author.*/

extern void set_diamond2_key(byte *external_key, /* Variable length key */
                        uint key_size,      /* Length of key in bytes */
                        uint rounds,        /* Number of rounds to use (5 to 15
                                           for Diamond, 4 to 30 for Diamond Lite) */
                        boolean invert,     /* true if mpj_decrypt may be called. */
                        int block_size);    /* 16 for Diamond; 8 for Diamond Lite. */
/* Call before the first call to diamond2_encrypt_block() or diamond2_decrypt_block */

extern void diamond2_encrypt_block(byte *x, byte *y);
/* Call set_diamond2_key() with a block_size of 16 before first calling
   diamond2_encrypt_block().   x is input, y is output.
*/

extern void diamond2_decrypt_block(byte *x, byte *y);
/* Call set_diamond2_key() with a block_size of 16 before first calling
   diamond2_decrypt_block().   x is input, y is output.
*/

extern void lite2_encrypt_block(byte *x, byte *y);
/* Call set_diamond2_key() with a block_size of 8 before first calling
   lite2_encrypt_block().   x is input, y is output.
*/

void lite2_decrypt_block(byte *x, byte *y);
/* Call set_diamond2_key() with a block_size of 8 before first calling
   lite2_decrypt_block().   x is input, y is output.
*/

extern void diamond2_done(void);
/* Clears internal keys.  Call after the last call to
diamond2_encrypt_block() or diamond2_decrypt_block() with a given key.  */


