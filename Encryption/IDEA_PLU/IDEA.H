#ifndef IDEA_H
#define IDEA_H

/*
 *	idea.h - header file for idea.c
 */

#include "usuals.h"  /* typedefs for byte, word16, boolean, etc. */

#define IDEAKEYSIZE 16
#define IDEABLOCKSIZE 8

#define IDEAROUNDS 8
#define IDEAKEYLEN (6*IDEAROUNDS+4)

/*
 * iv[] is used as a circular buffer.  bufleft is the number of
 * bytes at the end which have to be filled in before we crank
 * the block cipher again.  We do the block cipher operation
 * lazily: bufleft may be 0.  When we need one more byte, we
 * crank the block cipher and set bufleft to 7.
 */
struct IdeaCfbContext {
	byte iv[8];
	word16 key[IDEAKEYLEN];
	int bufleft;
};

struct IdeaRandContext {
	byte outbuf[8];
	word16 key[IDEAKEYLEN];
	int bufleft;
	byte internalbuf[8];
	byte timestamp[8];
};

void ideaCfbReinit(struct IdeaCfbContext *context, byte const *iv);
void ideaCfbInit(struct IdeaCfbContext *context, byte const (key[16]));
void ideaCfbDestroy(struct IdeaCfbContext *context);
void ideaCfbEncrypt(struct IdeaCfbContext *context,
		    byte const *src, byte *dest, int count);
void ideaCfbDecrypt(struct IdeaCfbContext *context,
		    byte const *src, byte *dest, int count);
void ideaRandInit(struct IdeaRandContext *context, byte const (key[16]),
		  byte const (seed[8]), word32 timestamp);
byte ideaRandByte(struct IdeaRandContext *c);

#endif /* !IDEA_H */
