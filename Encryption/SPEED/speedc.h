/*
 *  speedc.h:  header file for speedc.c
 *
 *  Reference:
 *       Y. Zheng:
 *       "The SPEED Cipher,"
 *       Financial Cryptography'97,
 *       Anquilla, BWI, 24-28 February 1997.
 *
 *  Author:     Yuliang Zheng
 *              School of Computing and Information Technology
 *              Monash University
 *              McMahons Road, Frankston 3199, Australia
 *              Email: yzheng@fcit.monash.edu.au
 *              URL:   http://www-pscit.fcit.monash.edu.au:/~yuliang/
 *              Voice: +61 3 9904 4196
 *              Fax  : +61 3 9904 4124
 *
 *  Date:       10 April    1996
 *               6 February 1997
 *
 *      Copyright (C) 1996, 1997 by Yuliang Zheng. All rights reserved. 
 *      This program may not be sold or used as inducement to
 *      sell a product without the written permission of the author.
 */

/*
 * The following three parameters 
 *      (1) SPEED_DATA_LEN
 *      (2) SPEED_KEY_LEN
 *      (3) SPEED_NO_OF_RND
 * may be modified.
 *
 * Suggested combinations for providing adequate security:
 *
 *  +--------------------------------------------------+
 *  | SPEED_DATA_LEN | SPEED_KEY_LEN | SPEED_NO_OF_RND |
 *  |==================================================|
 *  |       64       |     >= 64     |     >= 64       | 
 *  |--------------------------------------------------|
 *  |      128       |     >= 64     |     >= 48       | 
 *  |--------------------------------------------------|
 *  |      256       |     >= 64     |     >= 48       | 
 *  +--------------------------------------------------+
 */

#define SPEED_DATA_LEN    256     /* number of bits in a plain/ciphertext */
                                   /* = 64, 128 or 256 */
#define SPEED_KEY_LEN     128      /* number of bits in a key */
                                   /* = 48, 64, ..., or 256, divisible by 16 */
#define SPEED_NO_OF_RND    48      /* number of rounds */
                                   /* = 32, 36, ..., divisible by  4 */

/*
 *
 * The following should NOT be modified.
 * -------------------------------------
 *
 */

/*
 * speed_word defines a SPEED internal word 
 * as an unsigned integer of 32 or more bits.
 *
 * Note: 
 *       lower  8 bits are used when SPEED_DATA_LEN = 64 
 *       lower 16 bits are used when SPEED_DATA_LEN = 128 
 *       lower 32 bits are used when SPEED_DATA_LEN = 256 
 */
typedef unsigned long  speed_word;              /* unsigned int of >= 32 bits */

#define SPEED_DATA_LEN_BYTE (SPEED_DATA_LEN/8)  /* no. of bytes in a p/c-text */
#define SPEED_KEY_LEN_BYTE  (SPEED_KEY_LEN/8)   /* no. of bytes in a key */

typedef unsigned char speed_key [SPEED_KEY_LEN_BYTE];  /* for user key */
typedef unsigned char speed_data[SPEED_DATA_LEN_BYTE]; /* for p/c-text */

typedef speed_word speed_ikey [SPEED_NO_OF_RND];/* for round keys */
typedef speed_word speed_idata[8];              /* for internal p/c-text */

/*
 * Interface I: character-oriented interface.
 */
void speed_encrypt (
      speed_data ptxt,   /* plaintext,  an array of SPEED_DATA_LEN_BYTE chars */
      speed_data ctxt,   /* ciphertext, an array of SPEED_DATA_LEN_BYTE chars */
      speed_key  key     /* user key,   an array of SPEED_KEY_LEN_BYTE  chars */
      );
void speed_decrypt (
      speed_data ptxt,   /* plaintext,  an array of SPEED_DATA_LEN_BYTE chars */
      speed_data ctxt,   /* ciphertext, an array of SPEED_DATA_LEN_BYTE chars */
      speed_key  key     /* user key,   an array of SPEED_KEY_LEN_BYTE  chars */
      );
/*
 * Interface II: internal word-oriented interface.
 *    (As the key scheduling may be called only once,
 *     this interface may be more efficient than Interface I)
 */
void speed_key_schedule (
      speed_key  key,    /* user key,   an array of SPEED_KEY_LEN_BYTE chars */
      speed_ikey ikey    /* round key,  an array of SPEED_NO_OF_RND words */ 
      );
void speed_encrypt_rk (
      speed_idata iptxt, /* internal plaintext,  an array of 8 words */ 
      speed_idata ictxt, /* internal ciphertext, an array of 8 words */ 
      speed_ikey  ikey   /* round key,  an array of SPEED_NO_OF_RND words */ 
      );
void speed_decrypt_rk (
      speed_idata iptxt, /* internal plaintext,  an array of 8 words */ 
      speed_idata ictxt, /* internal ciphertext, an array of 8 words */ 
      speed_ikey  ikey   /* round key,  an array of SPEED_NO_OF_RND words */ 
      );

