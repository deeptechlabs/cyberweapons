/* cryptmpj.h -- programmer interface to the mpj block cipher.  All encryption
and decryption is done on 16 byte blocks. */

extern void set_mpj_key(byte *external_key, // Variable length key
                        uint key_size,      // Length of key
                        uint rounds,        // Number of rounds to use (5 to 15)
                        boolean invert);    // true if mpj_decrypt may be called.
/* Call before the first call to mpj_encrypt_block() or mpj_decrypt_block */

extern void mpj_encrypt_block(byte *x, byte *y);
/* Call makesbox() before first calling mpj_encrypt_block().
   x is input, y is output.
*/

extern void mpj_decrypt_block(byte *x, byte *y);
/* Call makesbox() and makesi() before first calling mpj_decrypt_block()
   x is input, y is output.
*/

extern void mpj_done(void);
/* Clears internal keys.  Call after the last call to
mpj_encrypt_block() or mpj_decrypt_block() with a given key.  */

