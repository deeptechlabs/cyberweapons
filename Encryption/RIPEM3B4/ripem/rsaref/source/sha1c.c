/* This work is derived from the RSA Data Security, Inc. MD5 Message-
   Digest Algorithm, file md5c.c.

   License to copy and use this software is granted provided that these
   notices are retained in any copies of any part of this documentation
   and/or software.  

   License is also granted to make and use derivative works provided
   that such works are identified as "derived from the RSA Data
   Security, Inc. MD5 Message-Digest Algorithm" in all material
   mentioning or referencing the derived work.  
                                                                    
   No representations are made concerning either the merchantability of
   this software or the suitability of this software for any particular
   purpose. It is provided "as is" without express or implied warranty
   of any kind.  
 */

/* SHA-1 Message Digest algorithm implemented according to FIPS PUB 180-1
 */

#include "global.h"
#include "sha1.h"

static void SHA1Transform PROTO_LIST ((UINT4 [5], unsigned char [64]));
static void SHA1Encode PROTO_LIST
  ((unsigned char *, UINT4 *, unsigned int));
static void SHA1Decode PROTO_LIST
  ((UINT4 *, unsigned char *, unsigned int));
static void SHA1_memcpy PROTO_LIST ((POINTER, POINTER, unsigned int));
static void SHA1_memset PROTO_LIST ((POINTER, int, unsigned int));

static unsigned char PADDING[64] = {
  0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* Define basic f() functions for rounds 1, 2, 3 and 4.
 */
#define F1(b, c, d) (((b) & (c)) | ((~b) & (d)))
#define F2(b, c, d) ((b) ^ (c) ^ (d))
#define F3(b, c, d) (((b) & (c)) | ((b) & (d)) | ((c) & (d)))
#define F4(b, c, d) ((b) ^ (c) ^ (d))

/* ROTATE_LEFT rotates x left n bits.
 */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* This is used in ROUND2, ROUND3 and ROUND4 to perform the step
     of mixing up the w array.
   Rotation is separate from xor to prevent recomputation.
   Assume that UINT4 w[16] is declared.
 */
#define MIX_W(s) { \
    w[(s)] ^= w[((s) + 13) & 0xf] ^ w[((s) + 8) & 0xf] ^ w[((s) + 2) & 0xf]; \
    w[(s)] = ROTATE_LEFT (w[(s)], 1); \
  }

/* These are transformations for rounds 1, 2, 3, and 4.
   Assume that UINT4 a, b, c, d, e, w[16], temp is declared.
 */
#define ROUND1(s) { \
    temp = ROTATE_LEFT (a, 5) + F1 (b, c, d) + e + w[(s)] + 0x5a827999;\
    e = d; d = c; c = ROTATE_LEFT (b, 30); b = a; a = temp; \
  }
#define ROUND2(s) { \
    MIX_W (s); \
    temp = ROTATE_LEFT (a, 5) + F2 (b, c, d) + e + w[(s)] + 0x6ed9eba1;\
    e = d; d = c; c = ROTATE_LEFT (b, 30); b = a; a = temp; \
  }
#define ROUND3(s) { \
    MIX_W (s); \
    temp = ROTATE_LEFT (a, 5) + F3 (b, c, d) + e + w[(s)] + 0x8f1bbcdc;\
    e = d; d = c; c = ROTATE_LEFT (b, 30); b = a; a = temp; \
  }
#define ROUND4(s) { \
    MIX_W (s); \
    temp = ROTATE_LEFT (a, 5) + F4 (b, c, d) + e + w[(s)] + 0xca62c1d6;\
    e = d; d = c; c = ROTATE_LEFT (b, 30); b = a; a = temp; \
  }

/* SHA1 initialization. Begins an SHA1 operation, writing a new context.
 */
void SHA1Init (context)
SHA1_CTX *context;                                                /* context */
{
  context->count[0] = context->count[1] = 0;

  /* Load magic initialization constants.
   */
  context->state[0] = 0x67452301;
  context->state[1] = 0xefcdab89;
  context->state[2] = 0x98badcfe;
  context->state[3] = 0x10325476;
  context->state[4] = 0xc3d2e1f0;
}

/* SHA1 block update operation. Continues an SHA1 message-digest
     operation, processing another message block, and updating the
     context.
 */
void SHA1Update (context, input, inputLen)
SHA1_CTX *context;                                                /* context */
unsigned char *input;                                         /* input block */
unsigned int inputLen;                              /* length of input block */
{
  unsigned int i, index, partLen;

  /* Compute number of bytes mod 64 */
  index = (unsigned int)((context->count[1] >> 3) & 0x3F);

  /* Update number of bits */
  if ((context->count[1] += ((UINT4)inputLen << 3)) < ((UINT4)inputLen << 3))
    context->count[0]++;
  context->count[0] += ((UINT4)inputLen >> 29);
  
  partLen = 64 - index;
  
  /* Transform as many times as possible.
   */
  if (inputLen >= partLen) {
    SHA1_memcpy ((POINTER)&context->buffer[index], (POINTER)input, partLen);
    SHA1Transform (context->state, context->buffer);
  
    for (i = partLen; i + 63 < inputLen; i += 64)
      SHA1Transform (context->state, &input[i]);
    
    index = 0;
  }
  else
    i = 0;
  
  /* Buffer remaining input */
  SHA1_memcpy
    ((POINTER)&context->buffer[index], (POINTER)&input[i], inputLen-i);
}

/* SHA1 finalization. Ends an SHA1 message-digest operation, writing the
     the message digest and zeroizing the context.
   Assume digest is a buffer at least 20 bytes long.
 */
void SHA1Final (digest, context)
unsigned char *digest;                                     /* message digest */
SHA1_CTX *context;                                                /* context */
{
  unsigned char bits[8];
  unsigned int index, padLen;

  /* Save number of bits. Note that count[0] is already the high-order word. */
  SHA1Encode (bits, context->count, 8);

  /* Pad out to 56 mod 64.
   */
  index = (unsigned int)((context->count[1] >> 3) & 0x3f);
  padLen = (index < 56) ? (56 - index) : (120 - index);
  SHA1Update (context, PADDING, padLen);
  
  /* Append length */
  SHA1Update (context, bits, 8);

  /* Store state in digest */
  SHA1Encode (digest, context->state, 20);
  
  /* Zeroize sensitive information.
   */
  SHA1_memset ((POINTER)context, 0, sizeof (*context));
}

/* SHA1 basic transformation. Transforms state based on block.
 */
static void SHA1Transform (state, block)
UINT4 state[5];
unsigned char block[64];
{
  UINT4 a, b, c, d, e, w[16], temp;

  /* Use the second method outlined which only needs a 16 word w buffer. */

  SHA1Decode (w, block, 64);

  a = state[0];
  b = state[1];
  c = state[2];
  d = state[3];
  e = state[4];

  /* Divide into four rounds where round 1 when 0 <= t <= 19, round 2 when
       20 <= t <= 39, round 3 when 40 <= t <= 59, and round 4 when
       60 <= t <= 79. */
  ROUND1 (0);
  ROUND1 (1);
  ROUND1 (2);
  ROUND1 (3);
  ROUND1 (4);
  ROUND1 (5);
  ROUND1 (6);
  ROUND1 (7);
  ROUND1 (8);
  ROUND1 (9);
  ROUND1 (10);
  ROUND1 (11);
  ROUND1 (12);
  ROUND1 (13);
  ROUND1 (14);
  ROUND1 (15);
  /* For the rest of round 1 we need to explicitly mix w since the ROUND1
       macro doesn't do it. */
  MIX_W (0); ROUND1 (0);
  MIX_W (1); ROUND1 (1);
  MIX_W (2); ROUND1 (2);
  MIX_W (3); ROUND1 (3);

  /* From now on, the macro will mix w. */
  ROUND2 (4);
  ROUND2 (5);
  ROUND2 (6);
  ROUND2 (7);
  ROUND2 (8);
  ROUND2 (9);
  ROUND2 (10);
  ROUND2 (11);
  ROUND2 (12);
  ROUND2 (13);
  ROUND2 (14);
  ROUND2 (15);
  ROUND2 (0);
  ROUND2 (1);
  ROUND2 (2);
  ROUND2 (3);
  ROUND2 (4);
  ROUND2 (5);
  ROUND2 (6);
  ROUND2 (7);

  ROUND3 (8);
  ROUND3 (9);
  ROUND3 (10);
  ROUND3 (11);
  ROUND3 (12);
  ROUND3 (13);
  ROUND3 (14);
  ROUND3 (15);
  ROUND3 (0);
  ROUND3 (1);
  ROUND3 (2);
  ROUND3 (3);
  ROUND3 (4);
  ROUND3 (5);
  ROUND3 (6);
  ROUND3 (7);
  ROUND3 (8);
  ROUND3 (9);
  ROUND3 (10);
  ROUND3 (11);

  ROUND4 (12);
  ROUND4 (13);
  ROUND4 (14);
  ROUND4 (15);
  ROUND4 (0);
  ROUND4 (1);
  ROUND4 (2);
  ROUND4 (3);
  ROUND4 (4);
  ROUND4 (5);
  ROUND4 (6);
  ROUND4 (7);
  ROUND4 (8);
  ROUND4 (9);
  ROUND4 (10);
  ROUND4 (11);
  ROUND4 (12);
  ROUND4 (13);
  ROUND4 (14);
  ROUND4 (15);

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
  
  /* Zeroize sensitive information.
   */
  SHA1_memset ((POINTER)w, 0, sizeof (w));
  a = b = c = d = e = temp = 0;
}

/* Encodes input (UINT4) into output (unsigned char). Assumes len is
     a multiple of 4.  Treat the output as high-byte first.
 */
static void SHA1Encode (output, input, len)
unsigned char *output;
UINT4 *input;
unsigned int len;
{
  unsigned int i, j;

  for (i = 0, j = 0; j < len; i++, j += 4) {
    output[j + 3] = (unsigned char)(input[i] & 0xff);
    output[j + 2] = (unsigned char)((input[i] >> 8) & 0xff);
    output[j + 1] = (unsigned char)((input[i] >> 16) & 0xff);
    output[j] = (unsigned char)((input[i] >> 24) & 0xff);
  }
}

/* Decodes input (unsigned char) into output (UINT4). Assumes len is
     a multiple of 4.  Treat the input buffer as high-byte first.
 */
static void SHA1Decode (output, input, len)
UINT4 *output;
unsigned char *input;
unsigned int len;
{
  unsigned int i, j;

  for (i = 0, j = 0; j < len; i++, j += 4)
    output[i] = ((UINT4)input[j + 3]) | (((UINT4)input[j + 2]) << 8) |
      (((UINT4)input[j + 1]) << 16) | (((UINT4)input[j]) << 24);
}

/* Note: Replace "for loop" with standard memcpy if possible.
 */
static void SHA1_memcpy (output, input, len)
POINTER output;
POINTER input;
unsigned int len;
{
  unsigned int i;
  
  for (i = 0; i < len; i++)
    output[i] = input[i];
}

/* Note: Replace "for loop" with standard memset if possible.
 */
static void SHA1_memset (output, value, len)
POINTER output;
int value;
unsigned int len;
{
  unsigned int i;
  
  for (i = 0; i < len; i++)
    ((char *)output)[i] = (char)value;
}
