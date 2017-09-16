/*
 *	Random byte interface to truerand()
 *	Matt Blaze 5/95
 *	eight really random bits
 *	usage: 
 *		unsigned char r; int randbyte();
 *		r=randbyte();
 *	randbyte() takes about .3 seconds on most machines.
 */
/*
 * The author of this software is Matt Blaze.
 *              Copyright (c) 1995 by AT&T.
 * Permission to use, copy, and modify this software without fee
 * is hereby granted, provided that this entire notice is included in
 * all copies of any software which is or includes a copy or
 * modification of this software and in all copies of the supporting
 * documentation for such software.
 *
 * This software may be subject to United States export controls.
 *
 * THIS SOFTWARE IS BEING PROVIDED "AS IS", WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTY.  IN PARTICULAR, NEITHER THE AUTHORS NOR AT&T MAKE ANY
 * REPRESENTATION OR WARRANTY OF ANY KIND CONCERNING THE MERCHANTABILITY
 * OF THIS SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR PURPOSE.
 */

int randbyte()
{
	unsigned long truerand();
	unsigned char *shs();
	unsigned long r[2];
	unsigned char *hash;

	r[0]=truerand(); r[1]=truerand();
	hash = shs(r,sizeof(r));
#ifdef DEBUGRND
	printf("%011o %011o %02x\n",r[0],r[1],*hash & 0xff);
#endif
	return ((int) (*hash)) & 0xff;
}
