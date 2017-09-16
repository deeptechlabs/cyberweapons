/* R_ENCODE.C - RFC 1113 encoding and decoding routines
 */

/* Copyright (C) 1991-2 RSA Laboratories, a division of RSA Data
   Security, Inc. All rights reserved.
 */
/* Code performance-enhanced with lookup tables by Richard Outerbridge,
 * October 1992
 */

#include "global.h"
#include "rsaref.h"

/* RFC 1113 encoding:

   Value Encoding  Value Encoding  Value Encoding  Value Encoding
       0 A            17 R            34 i            51 z
       1 B            18 S            35 j            52 0
       2 C            19 T            36 k            53 1
       3 D            20 U            37 l            54 2
       4 E            21 V            38 m            55 3
       5 F            22 W            39 n            56 4
       6 G            23 X            40 o            57 5
       7 H            24 Y            41 p            58 6
       8 I            25 Z            42 q            59 7
       9 J            26 a            43 r            60 8
      10 K            27 b            44 s            61 9
      11 L            28 c            45 t            62 +
      12 M            29 d            46 u            63 /
      13 N            30 e            47 v
      14 O            31 f            48 w         (pad) =
      15 P            32 g            49 x
      16 Q            33 h            50 y

#define ENCODING(i) \
  (unsigned char)(((i) < 26) ? ((i) + 0x41) : \
                  (((i) < 52) ? ((i) - 26 + 0x61) : \
                   (((i) < 62) ? ((i) - 52 + 0x30) : \
                    (((i) == 62) ? 0x2b : 0x2f))))

#define IS_ENCODING(c) \
  ((((c) >= 0x41) && ((c) <= 0x5a)) || \
   (((c) >= 0x61) && ((c) <= 0x7a)) || \
   (((c) >= 0x30) && ((c) <= 0x39)) || \
   ((c) == 0x2b) || \
   ((c) == 0x2f))
   
#define DECODING(c) \
  (((c) == 0x2b) ? 62 : \
   (((c) == 0x2f) ? 63 : \
    (((c) <= 0x39) ? ((c) - 0x30 + 52) : \
     (((c) <= 0x5a) ? ((c) - 0x41) : ((c) - 0x61 + 26)))))

*/

static unsigned char Encoded[64] = {

/*	ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/ */

	65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,
	86,87,88,89,90,97,98,99,100,101,102,103,104,105,106,107,108,109,
	110,111,112,113,114,115,116,117,118,119,120,121,122,48,49,50,51,
	52,53,54,55,56,57,43,47 };
	
static short Is_Encoded[256] = {
/*				0 1 2 3 4 5 6 7 8 9 a b c d e f */
/* 00 - 0f */	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
/* 10 - 1f */	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
/* 20 - 2f */	0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,1,
/* 30 - 3f */	1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,
/* 40 - 4f */	0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
/* 50 - 5f */	1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,
/* 60 - 6f */	0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
/* 70 - 7f */	1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,
/* 80 - 8f */	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
/* 90 - 9f */	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
/* a0 - af */	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
/* b0 - bf */	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
/* c0 - cf */	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
/* d0 - df */	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
/* e0 - ef */	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
/* f0 - ff */	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0	};

#define ENCODING_PAD 0x3d

#define IS_ENCODING(c) (Is_Encoded[(c)])

/* assumes IS_ENCODING (c) == 1 */

static unsigned char Decoded[128] = {
/*				 0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f */
/* 00 - 0f */	 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/* 10 - 1f */	 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/* 20 - 2f */	 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,62, 0, 0, 0,63,
/* 30 - 3f */	52,53,54,55,56,57,58,59,60,61, 0, 0, 0, 0, 0, 0,
/* 40 - 4f */	 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
/* 50 - 5f */	15,16,17,18,19,20,21,22,23,24,25, 0, 0, 0, 0, 0,
/* 60 - 6f */	 0,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
/* 70 - 7f */	41,42,43,44,45,46,47,48,49,50,51, 0, 0, 0, 0, 0	};
  
static void EncodeQuantum PROTO_LIST ((unsigned char [4], unsigned char [3]));
static int DecodeQuantum PROTO_LIST ((unsigned char [3], unsigned char [4]));
static void EncodeLastQuantum
  PROTO_LIST ((unsigned char [4], unsigned char *, unsigned int));
static int DecodeLastQuantum
  PROTO_LIST ((unsigned char *, unsigned int *, unsigned char [4]));

int R_EncodePEMBlock (encodedBlock, encodedBlockLen, block, blockLen)
unsigned char *encodedBlock;                               /* encoded block */
unsigned int *encodedBlockLen;                   /* length of encoded block */
unsigned char *block;                                              /* block */
unsigned int blockLen;                                   /* length of block */
{
  unsigned int i, lastLen;
  
  if (blockLen < 1) {
    *encodedBlockLen = 0;
    return( 0 );
  }
  
  for (i = 0; i < (blockLen-1)/3; i++)
    EncodeQuantum (&encodedBlock[4*i], &block[3*i]);
  
  lastLen = blockLen - 3*i;
  EncodeLastQuantum (&encodedBlock[4*i], &block[3*i], lastLen);
  *encodedBlockLen = 4*i + 4;
  return( 0 );
}
                    
int R_DecodePEMBlock (block, blockLen, encodedBlock, encodedBlockLen)
unsigned char *block;                                              /* block */
unsigned int *blockLen;                                  /* length of block */
unsigned char *encodedBlock;                               /* encoded block */
unsigned int encodedBlockLen;                    /* length of encoded block */
{
  int status;
  unsigned int i, lastLen;

  if (encodedBlockLen % 4)
    return (RE_ENCODING);
  
  if (encodedBlockLen < 1) {
    *blockLen = 0;
    return (0);
  }
  
  for (i = 0; i < (encodedBlockLen-1)/4; i++)
    if ((status = DecodeQuantum (&block[3*i], &encodedBlock[4*i])) != 0)
      return (status);
    
  if ((status = DecodeLastQuantum (&block[3*i], &lastLen, &encodedBlock[4*i]))
      != 0)
    return (status);

  *blockLen = 3*i + lastLen;
  return (0);
}

static void EncodeQuantum (encodedQuantum, quantum)
unsigned char encodedQuantum[4];
unsigned char quantum[3];
{
  UINT4 temp;
  unsigned int a, b, c, d;
  
  temp = ((UINT4)quantum[0]) << 16;
  temp |= ((UINT4)quantum[1]) << 8;
  temp |= (UINT4)quantum[2];
  
  a = (unsigned int)((temp >> 18) & 0x3f);
  b = (unsigned int)((temp >> 12) & 0x3f);
  c = (unsigned int)((temp >> 6) & 0x3f);
  d = (unsigned int)(temp & 0x3f);

  encodedQuantum[0] = Encoded[a];
  encodedQuantum[1] = Encoded[b];
  encodedQuantum[2] = Encoded[c];
  encodedQuantum[3] = Encoded[d];

  /* Zeroize potentially sensitive information.
   */
  temp = 0;
  a = b = c = d = 0;
}

static int DecodeQuantum (quantum, encodedQuantum)
unsigned char quantum[3];
unsigned char encodedQuantum[4];
{
  UINT4 temp;
  unsigned int a, b, c, d;
  
  if (! IS_ENCODING (encodedQuantum[0]) ||
      ! IS_ENCODING (encodedQuantum[1]) ||
      ! IS_ENCODING (encodedQuantum[2]) ||
      ! IS_ENCODING (encodedQuantum[3]))
    return (RE_ENCODING);
  
  a = Decoded[encodedQuantum[0]];
  b = Decoded[encodedQuantum[1]];
  c = Decoded[encodedQuantum[2]];
  d = Decoded[encodedQuantum[3]];
  
  temp = ((UINT4)a) << 18;
  temp |= ((UINT4)b) << 12;
  temp |= ((UINT4)c) << 6;
  temp |= (UINT4)d;

  quantum[0] = (unsigned char)(temp >> 16);
  quantum[1] = (unsigned char)(temp >> 8);
  quantum[2] = (unsigned char)temp;
  
  /* Zeroize potentially sensitive information.
   */
  temp = 0;
  a = b = c = d = 0;

  return (0);
}

static void EncodeLastQuantum (encodedQuantum, quantum, quantumLen)
unsigned char encodedQuantum[4];
unsigned char *quantum;
unsigned int quantumLen;                                       /* 1, 2 or 3 */
{
  UINT4 temp;
  unsigned int a, b, c, d;

  temp = ((UINT4)quantum[0]) << 16;
  if (quantumLen >= 2)
    temp |= ((UINT4)quantum[1]) << 8;
  if (quantumLen == 3)
    temp |= ((UINT4)quantum[2]);
  
  a = (unsigned int)((temp >> 18) & 0x3f);
  b = (unsigned int)((temp >> 12) & 0x3f);
  if (quantumLen >= 2)
    c = (unsigned int)((temp >> 6) & 0x3f);
  if (quantumLen == 3)
    d = (unsigned int)(temp & 0x3f);

  encodedQuantum[0] = Encoded[a];
  encodedQuantum[1] = Encoded[b];
  if (quantumLen >= 2)
    encodedQuantum[2] = Encoded[c];
  else
    encodedQuantum[2] = ENCODING_PAD;
  if (quantumLen == 3)
    encodedQuantum[3] = Encoded[d];
  else
    encodedQuantum[3] = ENCODING_PAD;

  /* Zeroize potentially sensitive information.
   */
  temp = 0;
  a = b = c = d = 0;
}

static int DecodeLastQuantum (quantum, quantumLen, encodedQuantum)
unsigned char *quantum;
unsigned int *quantumLen;                                      /* 1, 2 or 3 */
unsigned char encodedQuantum[4];
{
  UINT4 temp;
  unsigned int a, b, c, d;
  
  if (! IS_ENCODING (encodedQuantum[0]) ||
      ! IS_ENCODING (encodedQuantum[1]) ||
      (! IS_ENCODING (encodedQuantum[2]) &&
       (encodedQuantum[2] != ENCODING_PAD)) ||
      (! IS_ENCODING (encodedQuantum[3]) &&
       (encodedQuantum[3] != ENCODING_PAD)))
    return (RE_ENCODING);
        
  if (encodedQuantum[2] == ENCODING_PAD)
    *quantumLen = 1;
  else if (encodedQuantum[3] == ENCODING_PAD)
    *quantumLen = 2;
  else
    *quantumLen = 3;
  
  a = Decoded[encodedQuantum[0]];
  b = Decoded[encodedQuantum[1]];
  if (*quantumLen >= 2)
    c = Decoded[encodedQuantum[2]];
  if (*quantumLen == 3)
    d = Decoded[encodedQuantum[3]];
  
  temp = ((UINT4)a) << 18;
  temp |= ((UINT4)b) << 12;
  if (*quantumLen >= 2)
    temp |= ((UINT4)c) << 6;
  if (*quantumLen == 3)
    temp |= ((UINT4)d);

  quantum[0] = (unsigned char)(temp >> 16);
  if (*quantumLen >= 2)
    quantum[1] = (unsigned char)(temp >> 8);
  if (*quantumLen == 3)
    quantum[2] = (unsigned char)temp;
  
  /* Zeroize potentially sensitive information.
   */
  temp = 0;
  a = b = c = d = 0;
  
  return (0);
}
