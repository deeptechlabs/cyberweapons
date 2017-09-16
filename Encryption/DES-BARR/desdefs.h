#define BLOCKBITS	64		/* bits per block */
#define KEYBITS		56		/* bits per key */
#define STAGECOUNT	16		/* number of stages */
#define DES_BLOCKSIZE	8		/* bytes per block */

#define BASE		1		/* a kludge for 0 vs 1 arrays */

typedef unsigned char  u8;
typedef unsigned short u16;
typedef	unsigned long  u32;
typedef		 long  s32;

typedef u8	bit;			/* 1 bit quantity */
typedef u8	u4;			/* 4 bit quantity */
typedef u8	u6;			/* 6 bit quantity */

typedef u8 	blockBitIndex;		/* 1..BLOCKBITS */
typedef u8	keyBitIndex;		/* 1..KEYBITS */

typedef blockBitIndex	bitIndex;	/* generic index into a bitVector */
typedef bitIndex	bitIndexVector[];	/* a vector of bit indices */

typedef	bit		blockType[BLOCKBITS];

typedef struct {
   u32		left;				/* Lowest address = bit 1 */
   u32		right;				/* Highest address = bit 64 */
} desPair;

typedef	u6		u6Block[8];		/* Optimization 6 */

#ifndef NEWDES
typedef	u6Block		keyVector[STAGECOUNT];	/* Optimization 6 */
#else
typedef	desPair		keyVector[STAGECOUNT];	/* Optimization 6 */
#endif

typedef	u4		stageRange;		/* 1..STAGECOUNT */

typedef union {
   desPair	pair;
   u8 		bytes[8];			/* 0 = LSB, 7 = MSB */
} desUnion;

typedef struct {
   u8		decr;			/* encrypt, decrypt flag */
   keyVector 	bits;
} desKeyType;

extern u32 sBoxp[8][64];
