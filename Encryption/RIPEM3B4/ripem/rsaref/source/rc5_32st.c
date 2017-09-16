/* This is a stub file for the RSAREF source code distribution so
     that r_enhanc.c can link to something.  Licensed versions of
     RSAREF can link to a "real" rc5 object file.
 */

#include "global.h"
#include "rsaref.h"
#include "rc5_32.h"

/* For the "stub" version, return an error.
 */
int RC5_32_CBCInit (context, key, keyBytes, rounds, iv, encrypt)
RC5_32_CBC_CTX *context;                                         /* context */
unsigned char *key;                                                  /* key */
unsigned int keyBytes;                              /* size of key in bytes */
unsigned int rounds;                                    /* number of rounds */
unsigned char *iv;                                   /* initializing vector */
int encrypt;                     /* encrypt flag (1 = encrypt, 0 = decrypt) */
{
UNUSED_ARG (context)
UNUSED_ARG (key)
UNUSED_ARG (keyBytes)
UNUSED_ARG (rounds)
UNUSED_ARG (iv)
UNUSED_ARG (encrypt)
  return (RE_ENCRYPTION_ALGORITHM);
}

/* For the "stub" version, return an error.
 */
int RC5_32_CBCUpdate (context, output, input, len)
RC5_32_CBC_CTX *context;                                         /* context */
unsigned char *output;                                      /* output block */
unsigned char *input;                                        /* input block */
unsigned int len;                      /* length of input and output blocks */
{
UNUSED_ARG (context)
UNUSED_ARG (output)
UNUSED_ARG (input)
UNUSED_ARG (len)
  return (RE_ENCRYPTION_ALGORITHM);
}

void RC5_32_CBCRestart (context)
RC5_32_CBC_CTX *context;
{
UNUSED_ARG (context)
}

