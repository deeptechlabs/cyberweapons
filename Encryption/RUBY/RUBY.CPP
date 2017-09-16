/* Ruby.cpp -- ruby hash cipher MARK 5 prototype

Copyright (C) 1994-1996 Michael Paul Johnson.  All rights reserved.
Inventor and author: Michael Paul Johnson.
Date invented: 27 July 1994.
Mark 5 modification: 4 January 1996

You may use and distribute this software without payment of royalties
provided that you retain this copyright notice in the source code and
that you do not misrepresent the source of this software.  You are
responsible for compliance with any applicable export regulations.

Note that this is experimental software that implements and describes
an experimental algorithm.  Use it at your own risk.  Neither I nor
Exabyte Corporation will be held responsible for any damages caused by
this program or algorithm.

*/

#ifdef __MSDOS__
#include <mem.h>
#else
#include <memory.h>
#endif

/* #define BIG_ENDIAN /* If machine is MSByte First, for compatibility. */

/*

The STRENGTH constant is where you get to trade off cryptographic
strength and speed.  The following nonscientific table is presented
as a guideline for selecting a constant.  More study is needed before
the cryptographic strength associated with the value of this constant
can be assigned a more meaningful measure.

4   Minimum       -  speed is of the essence, security secondary.
8   Desk lock     -  reasonable compromise of speed vs security?
16  Dead bolt     -  probably good enough for most things.
20  Portable safe -  security is more important than speed.
32  Anchored safe -  speed isn't much of a concern.
40  Bank vault    -  your pentium has nothing better to do, anyway.
64  Fort Knox     -  If you are willing to wait this long, it would probably
                     make sense to double the block size, too.
*/

#define STRENGTH 8

/*

The family key is a set of two 32-bit integers with a "fairly even"
distribution of ones and zeroes.  These two numbers should not be a
power of 2 (i.e., they should be relatively prime to 0x100000000L).
This means that the effective family key length is a total of 62 bits,
since the two least significant bits are always 1.

This number has two functions.  The most important one is to help
spread the influence of key bits into the "zone" that affects the roll
operations. Another is to give you a convenient way to make your
algorithm "proprietary" to your application.  If interchange with
other Ruby Mark 5 implementations is important, I recommend the use
of 0x456C6091 and 0xAA7110C3.  The real strength is in the user's
key, not the family key, especially if you embed the family key in
the software.

Defining an enlarged user key of 126 bits and using the extra 62 bits
for the family key is an idea I considered, but I really can't
guarantee that this would really increase the security of the
algorithm as much as the key size would seem to indicate. (It
wouldn't be worse than a 64-bit key, but it probably wouldn't nearly
square the strength of the cipher, either).

*/

#define FAMILY_KEY_1 0x456C6091L
#define FAMILY_KEY_2 0xAA7110C3L

#define FASTER_NOT_SMALLER /* if speed is more important than code size.*/

#ifdef FASTER_NOT_SMALLER

/* Does your processor have a logical rotate instruction? If so, you can
   speed this up.
*/

#define roll(X, C) (((X)<<(int)(C))|((X)>>(32-(int)(C))))

#else

/*

Use the roll function instead of the macro if the space consumed by the
expansion of 12 roll macros consumes too much code space.  This might be
significant in some embedded applications.

*/

unsigned long roll(unsigned long X, unsigned long C)
    {
    return (X<<(int)C) | (X>>(32-(int)C));
    }

#endif

#define f1(A,B,C,D) (((roll(A,D&0x1F)+roll(B,C>>27))^(roll(C,B&0x1F)+roll(D,A>>27))))
#define f2(A,B,C,D) (((roll(A,C&0x1F)^roll(B,D>>27))+(roll(C,A&0x1F)+roll(D,B>>27))))


static unsigned char hash_state[8];
static unsigned char hash_partial[8];
static unsigned long hash_count;
static unsigned hash_position;

void byte_swap(unsigned char *X)
    {
    unsigned char b;

    b=X[0];X[0]=X[3];X[3]=b;
    b=X[1];X[1]=X[2];X[2]=b;
    }

void ruby_crypt(unsigned char *P, unsigned char *K, unsigned char *C)
    {
    int I, J, H, L, M;
    unsigned long X[4];
/*

    It is convenient to call this function with pointers to bytes, but
    the input and output are handled as unsigned longs.
    The key should be selected randomly.
*/

    X[0] = *((unsigned long *)P);
    X[1] = *(((unsigned long *)P)+1);
    X[2] = *((unsigned long *)K);
    X[3] = *(((unsigned long *)K)+1);
#ifdef BIG_ENDIAN
    byte_swap((unsigned char *)(X));
    byte_swap((unsigned char *)(X+1));
    byte_swap((unsigned char *)(X+2));
    byte_swap((unsigned char *)(X+3));
#endif

    for (I=0,J=0,H=1,L=2,M=3; I<(STRENGTH); I++)
        {
        X[J] = f1(X[J],X[H],X[L],X[M]);
		X[J] += FAMILY_KEY_1;
        J = (J+1)&3;
        H = (H+1)&3;
        L = (L+1)&3;
        M = (M+1)&3;
        X[J] = f2(X[J],X[H],X[L],X[M]);
        X[J] *= FAMILY_KEY_2;
        J = (J+1)&3;
        H = (H+1)&3;
        L = (L+1)&3;
        M = (M+1)&3;
        }

    *((unsigned long *)C) = roll(X[0], X[3]&0x1F) + roll(X[1], X[2]>>27);
    *(((unsigned long *)C)+1) = roll(X[2], X[0]>>27) ^ roll(X[3], X[1]&0x1F);

#ifdef BIG_ENDIAN
    byte_swap(C);
    byte_swap(C+4);
#endif
    }

void ruby_hash_init(void)
    {
    hash_position = 0;
    hash_count = 0L;
    memset(hash_state, 0, 8);
    }

void ruby_hash_update(unsigned char *b, unsigned count)
    {
    unsigned u;

    for (u=0; u<count; u++)
        {
        hash_partial[hash_position++] = *b++;
        if (hash_position >= 8)
            {
            ruby_crypt(hash_partial, hash_state, hash_state);
            hash_position = 0;
            }
        }
    hash_count += count;
    }

void ruby_hash_final(unsigned char *hash)
    {
#ifdef BIG_ENDIAN
    byte_swap((unsigned char *)(&hash_count));
#endif
    ruby_hash_update((unsigned char *) (&hash_count), 4);
    while (hash_position < 8)
        {
        hash_partial[hash_position++] = 0xFF;
        }
    ruby_crypt(hash_partial, hash_state, hash_state);
    memcpy(hash, hash_state, 8);
    }


