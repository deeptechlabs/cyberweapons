/* RX2, an algorithm compatible with RC2.
   RC2 is a registered trademark of RSA Data Security, Inc.
 */

#include "global.h"
#include "rsaref.h"
#include "rx2.h"

/* ROTATE_LEFT rotates UINT2 x left n bits.
 */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (16-(n))))

/* ROTATE_RIGHT rotates UINT2 x right n bits.
 */
#define ROTATE_RIGHT(x, n) (((x) >> (n)) | ((x) << (16-(n))))

/* Repeat PI_TABLE twice so that PI_TABLE[x+y] will be valid where
     both x and y are < 256. */
static unsigned char PI_TABLE[512] = {
  0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed, 0x28, 0xe9, 0xfd, 0x79, 0x4a, 0xa0, 0xd8, 0x9d,
  0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e, 0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2,
  0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3, 0x4f, 0x13, 0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32,
  0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b, 0xf0, 0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 0x82,
  0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c, 0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc,
  0x12, 0x75, 0xca, 0x1f, 0x3b, 0xbe, 0xe4, 0xd1, 0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26,
  0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57, 0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 0x03,
  0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7, 0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7,
  0x08, 0xe8, 0xea, 0xde, 0x80, 0x52, 0xee, 0xf7, 0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a,
  0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74, 0x4b, 0x9f, 0xd0, 0x5e, 0x04, 0x18, 0xa4, 0xec,
  0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc, 0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39,
  0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 0xb4, 0x7a, 0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31,
  0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae, 0x05, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba, 0xc9,
  0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c, 0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9,
  0x0d, 0x38, 0x34, 0x1b, 0xab, 0x33, 0xff, 0xb0, 0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e,
  0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77, 0x0a, 0xa6, 0x20, 0x68, 0xfe, 0x7f, 0xc1, 0xad,
  /* and now to repeat ... */
  0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed, 0x28, 0xe9, 0xfd, 0x79, 0x4a, 0xa0, 0xd8, 0x9d,
  0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e, 0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2,
  0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3, 0x4f, 0x13, 0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32,
  0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b, 0xf0, 0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 0x82,
  0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c, 0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc,
  0x12, 0x75, 0xca, 0x1f, 0x3b, 0xbe, 0xe4, 0xd1, 0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26,
  0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57, 0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 0x03,
  0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7, 0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7,
  0x08, 0xe8, 0xea, 0xde, 0x80, 0x52, 0xee, 0xf7, 0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a,
  0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74, 0x4b, 0x9f, 0xd0, 0x5e, 0x04, 0x18, 0xa4, 0xec,
  0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc, 0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39,
  0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 0xb4, 0x7a, 0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31,
  0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae, 0x05, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba, 0xc9,
  0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c, 0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9,
  0x0d, 0x38, 0x34, 0x1b, 0xab, 0x33, 0xff, 0xb0, 0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e,
  0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77, 0x0a, 0xa6, 0x20, 0x68, 0xfe, 0x7f, 0xc1, 0xad
};

static void PackUINT2 PROTO_LIST ((UINT2 *, unsigned char *));
static void UnpackUINT2 PROTO_LIST ((unsigned char *, UINT2 *));
static int RX2Key PROTO_LIST
  ((UINT2 *, unsigned char *, unsigned int, unsigned int));
static void RX2MixEncrypt PROTO_LIST ((UINT2 *, UINT2 *, unsigned int));
static void RX2MashEncrypt PROTO_LIST ((UINT2 *, UINT2 *));
static void RX2MixDecrypt PROTO_LIST ((UINT2 *, UINT2 *, unsigned int));
static void RX2MashDecrypt PROTO_LIST ((UINT2 *, UINT2 *));
static void RX2Encrypt PROTO_LIST ((UINT2 *, UINT2 *));
static void RX2Decrypt PROTO_LIST ((UINT2 *, UINT2 *));

/* Initialize context.  Caller must zeroize the context when finished.
   Returns 0 for success, RE_LEN if keyLen or effectiveBits out of range.
 */
int RX2_CBCInit (context, key, keyLen, iv, effectiveBits, encrypt)
RX2_CBC_CTX *context;                                            /* context */
unsigned char *key;                                                  /* key */
unsigned int keyLen;                                          /* key length */
unsigned char iv[8];                                 /* initializing vector */
unsigned int effectiveBits;                           /* effective key bits */
int encrypt;                     /* encrypt flag (1 = encrypt, 0 = decrypt) */
{
  int status;
  
  /* Copy encrypt flag to context.
   */
  context->encrypt = encrypt;

  /* Pack initializing vector into context.
   */
  PackUINT2 (context->iv, iv);

  /* Save the IV for use in Restart */
  context->originalIV[0] = context->iv[0];
  context->originalIV[1] = context->iv[1];
  context->originalIV[2] = context->iv[2];
  context->originalIV[3] = context->iv[3];

  /* Expand the key.
   */
  if ((status = RX2Key (context->keyBuffer, key, keyLen, effectiveBits)) != 0)
    return (status);

  return (0);
}

/* RX2-CBC block update operation. Continues a RX2-CBC encryption
   operation, processing eight-byte message blocks, and updating
   the context.
 */
int RX2_CBCUpdate (context, output, input, len)
RX2_CBC_CTX *context;                                            /* context */
unsigned char *output;                                      /* output block */
unsigned char *input;                                        /* input block */
unsigned int len;                      /* length of input and output blocks */
{
  UINT2 inputBlock[4], work[4];
  unsigned int i;
  
  if (len % 8)
    return (RE_LEN);

  for (i = 0; i < len/8; i++) {
    PackUINT2 (inputBlock, &input[8*i]);
        
    if (context->encrypt) {
      /* Chain.
       */
      work[0] = inputBlock[0] ^ context->iv[0];
      work[1] = inputBlock[1] ^ context->iv[1];
      work[2] = inputBlock[2] ^ context->iv[2];
      work[3] = inputBlock[3] ^ context->iv[3];

      RX2Encrypt (work, context->keyBuffer);

      context->iv[0] = work[0];
      context->iv[1] = work[1];
      context->iv[2] = work[2];
      context->iv[3] = work[3];
    }
    else {
      work[0] = inputBlock[0];
      work[1] = inputBlock[1];         
      work[2] = inputBlock[2];         
      work[3] = inputBlock[3];         

      RX2Decrypt (work, context->keyBuffer);

      /* Chain, then update IV.
       */
      work[0] ^= context->iv[0];
      work[1] ^= context->iv[1];
      work[2] ^= context->iv[2];
      work[3] ^= context->iv[3];
      context->iv[0] = inputBlock[0];
      context->iv[1] = inputBlock[1];
      context->iv[2] = inputBlock[2];
      context->iv[3] = inputBlock[3];
    }

    UnpackUINT2 (&output[8*i], work);
  }
  
  /* Zeroize sensitive information.
   */
  R_memset ((POINTER)inputBlock, 0, sizeof (inputBlock));
  R_memset ((POINTER)work, 0, sizeof (work));
  
  return (0);
}

void RX2_CBCRestart (context)
RX2_CBC_CTX *context;
{
  /* Reset to the original IV */
  context->iv[0] = context->originalIV[0];
  context->iv[1] = context->originalIV[1];
  context->iv[2] = context->originalIV[2];
  context->iv[3] = context->originalIV[3];
}

/* Pack 8 bytes out of the char array into 4 words of the UINT2 array.
   The char array is interpreted as little endian.
   into and outof may NOT point to the same buffer.
 */
static void PackUINT2 (into, outof)
UINT2 *into;
unsigned char *outof;
{
  *into    = *outof++ & 0xff;
  *into++ |= (*outof++ & 0xff) << 8;
  *into    = *outof++ & 0xff;
  *into++ |= (*outof++ & 0xff) << 8;
  *into    = *outof++ & 0xff;
  *into++ |= (*outof++ & 0xff) << 8;
  *into    = *outof++ & 0xff;
  *into   |= (*outof   & 0xff) << 8;
}

/* Unpack 4 words of the UINT2 array into 8 bytes of the char array.
   The char array is interpreted as little endian.
   into and outof may NOT point to the same buffer.
 */
static void UnpackUINT2 (into, outof)
unsigned char *into;
UINT2 *outof;
{
  *into++ = (unsigned char)( *outof         & 0xff);
  *into++ = (unsigned char)((*outof++ >> 8) & 0xff);
  *into++ = (unsigned char)( *outof         & 0xff);
  *into++ = (unsigned char)((*outof++ >> 8) & 0xff);
  *into++ = (unsigned char)( *outof         & 0xff);
  *into++ = (unsigned char)((*outof++ >> 8) & 0xff);
  *into++ = (unsigned char)( *outof         & 0xff);
  *into   = (unsigned char)((*outof   >> 8) & 0xff);
}

/* Expand the key into the 64 element UINT2 keyBuffer array.
   Note that key expansion is the same for encrypt and decrypt.
   Returns 0 for success, RE_LEN if keyLen or effectiveBits out of range.
 */
static int RX2Key (keyBuffer, key, keyLen, effectiveBits)
UINT2 *keyBuffer;
unsigned char *key;
unsigned int keyLen;
unsigned int effectiveBits;
{
  unsigned char *l, mask;
  unsigned int effectiveBytes;
  int i;

  if (keyLen < 1 || keyLen > 128)
    return (RE_LEN);
  if (effectiveBits < 1 || effectiveBits > 8*128)
    return (RE_LEN);

  /* Interpret the keyBuffer array as 128 byte l array.  (We will convert to
       UINT2 array at the end.) */
  l = (unsigned char *)keyBuffer;
  
  /* Place key at beginning of key buffer */
  R_memcpy ((POINTER)l, (POINTER)key, keyLen);

  /* Compute effective key length in bytes */
  effectiveBytes = (effectiveBits + 7) / 8;

  /* Compute mask which has its 8 - (8*effectiveBytes - effectiveBits)
       least significant bits set.  So we take 0xff and shift right
       by (8*effectiveBytes - effectiveBits). */
  mask = (unsigned char)
    ((unsigned int)0xff >> (8 * effectiveBytes - effectiveBits));

  /* First loop */
  for (i = keyLen; i <= 127; ++i)
    /* Note that PI_TABLE has the 256 bytes twice so the added l[]
         values will not go out of range. */
    l[i] = PI_TABLE[ l[i - 1] + l[i - keyLen] ];

  l[128 - effectiveBytes] = PI_TABLE[ l[128 - effectiveBytes] & mask];

  /* Second loop.
     Note that i is signed so it can go to -1, so i >= 0 can be false. */
  for (i = 127 - effectiveBytes; i >= 0; --i)
    l[i] = PI_TABLE[ l[i + 1] ^ l[i + effectiveBytes] ];

  /* Convert key buffer from a byte array to a UINT2 array.
     We can move keyBuffer as a pointer since we are done with it.
   */
  for (i = 0; i < 128; i += 2)
    *keyBuffer++ = (l[i] & 0xff) | ((l[i + 1] & 0xff) << 8);

  return (0);
}

/* j should increase by 4 on each call.
 */
static void RX2MixEncrypt (block, keyBuffer, j)
UINT2 *block;
UINT2 *keyBuffer;
unsigned int j;
{
  block[0] += keyBuffer[j] + (block[3] & block[2]) +
    ((~block[3]) & block[1]);
  /* rotate by s[0] */
  block[0] = ROTATE_LEFT (block[0], 1);
  ++j;

  block[1] += keyBuffer[j] + (block[0] & block[3]) +
    ((~block[0]) & block[2]);
  /* rotate by s[1] */
  block[1] = ROTATE_LEFT (block[1], 2);
  ++j;

  block[2] += keyBuffer[j] + (block[1] & block[0]) +
    ((~block[1]) & block[3]);
  /* rotate by s[2] */
  block[2] = ROTATE_LEFT (block[2], 3);
  ++j;

  block[3] += keyBuffer[j] + (block[2] & block[1]) +
    ((~block[2]) & block[0]);
  /* rotate by s[3] */
  block[3] = ROTATE_LEFT (block[3], 5);
}

static void RX2MashEncrypt (block, keyBuffer)
UINT2 *block;
UINT2 *keyBuffer;
{
  block[0] += keyBuffer[block[3] & 63];
  block[1] += keyBuffer[block[0] & 63];
  block[2] += keyBuffer[block[1] & 63];
  block[3] += keyBuffer[block[2] & 63];
}

/* j should decrease by 4 on each call, from 63 to 59, etc.
 */
static void RX2MixDecrypt (block, keyBuffer, j)
UINT2 *block;
UINT2 *keyBuffer;
unsigned int j;
{
  /* rotate by s[3] */
  block[3] = ROTATE_RIGHT (block[3], 5);
  block[3] -= keyBuffer[j] + (block[2] & block[1]) +
    ((~block[2]) & block[0]);
  --j;

  /* rotate by s[2] */
  block[2] = ROTATE_RIGHT (block[2], 3);
  block[2] -= keyBuffer[j] + (block[1] & block[0]) +
    ((~block[1]) & block[3]);
  --j;

  /* rotate by s[1] */
  block[1] = ROTATE_RIGHT (block[1], 2);
  block[1] -= keyBuffer[j] + (block[0] & block[3]) +
    ((~block[0]) & block[2]);
  --j;

  /* rotate by s[0] */
  block[0] = ROTATE_RIGHT (block[0], 1);
  block[0] -= keyBuffer[j] + (block[3] & block[2]) +
    ((~block[3]) & block[1]);
}

static void RX2MashDecrypt (block, keyBuffer)
UINT2 *block;
UINT2 *keyBuffer;
{
  block[3] -= keyBuffer[block[2] & 63];
  block[2] -= keyBuffer[block[1] & 63];
  block[1] -= keyBuffer[block[0] & 63];
  block[0] -= keyBuffer[block[3] & 63];
}

static void RX2Encrypt (block, keyBuffer)
UINT2 *block;
UINT2 *keyBuffer;
{
  RX2MixEncrypt (block, keyBuffer, 0);
  RX2MixEncrypt (block, keyBuffer, 4);
  RX2MixEncrypt (block, keyBuffer, 8);
  RX2MixEncrypt (block, keyBuffer, 12);
  RX2MixEncrypt (block, keyBuffer, 16);

  RX2MashEncrypt (block, keyBuffer);
  
  RX2MixEncrypt (block, keyBuffer, 20);
  RX2MixEncrypt (block, keyBuffer, 24);
  RX2MixEncrypt (block, keyBuffer, 28);
  RX2MixEncrypt (block, keyBuffer, 32);
  RX2MixEncrypt (block, keyBuffer, 36);
  RX2MixEncrypt (block, keyBuffer, 40);

  RX2MashEncrypt (block, keyBuffer);

  RX2MixEncrypt (block, keyBuffer, 44);
  RX2MixEncrypt (block, keyBuffer, 48);
  RX2MixEncrypt (block, keyBuffer, 52);
  RX2MixEncrypt (block, keyBuffer, 56);
  RX2MixEncrypt (block, keyBuffer, 60);
}

static void RX2Decrypt (block, keyBuffer)
UINT2 *block;
UINT2 *keyBuffer;
{
  RX2MixDecrypt (block, keyBuffer, 63);
  RX2MixDecrypt (block, keyBuffer, 59);
  RX2MixDecrypt (block, keyBuffer, 55);
  RX2MixDecrypt (block, keyBuffer, 51);
  RX2MixDecrypt (block, keyBuffer, 47);

  RX2MashDecrypt (block, keyBuffer);
  
  RX2MixDecrypt (block, keyBuffer, 43);
  RX2MixDecrypt (block, keyBuffer, 39);
  RX2MixDecrypt (block, keyBuffer, 35);
  RX2MixDecrypt (block, keyBuffer, 31);
  RX2MixDecrypt (block, keyBuffer, 27);
  RX2MixDecrypt (block, keyBuffer, 23);

  RX2MashDecrypt (block, keyBuffer);

  RX2MixDecrypt (block, keyBuffer, 19);
  RX2MixDecrypt (block, keyBuffer, 15);
  RX2MixDecrypt (block, keyBuffer, 11);
  RX2MixDecrypt (block, keyBuffer, 7);
  RX2MixDecrypt (block, keyBuffer, 3);
}
