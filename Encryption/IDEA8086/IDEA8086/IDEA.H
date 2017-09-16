/*
 * This code is placed in the public domain.
 * Recognition of its authorship, by Colin Plumb, would be appreciated,
 * but cannot be required under the law of "public domain."
 */
 
#define KEYSIZE (8*6+4)        /* 52 words, 104 bytes */
 
/* This is appropriate for MS-DOS */
typedef unsigned short uint16;
 
typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;
 
/* Functions from idea.c */
uint16 Mul(uint16 a, uint16 b);
void Idea(uchar *in, uchar *out, uint16 *key);

/* Functions from crypt.asm */
void Idea2(uchar *in, uchar *out, uint16 *key);
void IdeaCFB(uchar *IV, uint16 *key, uchar *plain, uchar *cipher, uint16 num);
void IdeaCFBx(uchar *IV, uint16 *key, uchar *cipher, uchar *plain, uint16 num);
