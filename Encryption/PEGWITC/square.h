#ifndef __SQUARE_H
#define __SQUARE_H

#define R 8	/* number of rounds */
#define SQUARE_BLOCKSIZE (4*sizeof(word32))

#ifndef USUAL_TYPES
#define USUAL_TYPES
	typedef unsigned char	byte;	/*  8 bit */
	typedef unsigned short	word16;	/* 16 bit */
#ifdef __alpha
	typedef unsigned int	word32;	/* 32 bit */
#else  /* !__alpha */
	typedef unsigned long	word32;	/* 32 bit */
#endif /* ?__alpha */
#endif /* ?USUAL_TYPES */

extern const char *squareBanner;

typedef byte squareBlock[SQUARE_BLOCKSIZE];
typedef word32 squareKeySchedule[R+1][4];

void squareGenerateRoundKeys (const squareBlock key,
	squareKeySchedule roundKeys_e, squareKeySchedule roundKeys_d);
void squareExpandKey (const squareBlock key, squareKeySchedule roundKeys_e);
void squareEncrypt (word32 text[4], squareKeySchedule roundKeys);
void squareDecrypt (word32 text[4], squareKeySchedule roundKeys);

#endif /* __SQUARE_H */
