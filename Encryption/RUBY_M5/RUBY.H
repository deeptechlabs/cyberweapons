/* Ruby.h -- Ruby hash cipher prototype

Copyright (C) 1994-1996 Michael Paul Johnson.  All rights reserved.
Inventor and author: Michael Paul Johnson.
Mark 5 modifications: 4 January 1996

The Ruby block cipher is really a small hash function that must be
used in an appropriate chaining method to be reversible.  In other
words, it lacks an electronic codebook mode.  On the other hand, the
electronic codebook mode is one of the least secure modes to use a
block cipher in.  The main advantages of the Ruby block cipher are
(1) speed in software implementations, (2) size, (3) no delay for key
setup (making key feedback modes practical), and (4) reasonable
security for the speed.

The speed of the Ruby cipher derives from the use of 32 bit
operations common to most computers, and from limiting the number of
operations per block encryption.  The operations used are add,
exclusive or, multiply, and logical rotate.

Because there is no separate key setup step to generate internal keys
from an external key, there is no performance penalty for changing
keys often.  This encourages the use of frequently changed session
keys.  It also makes feedback modes that continually change the key
practical.

The security of the Ruby cipher is based on the mixing of both
arithmetic and logical operations, including the very nonlinear
rotation operation, in a finite set of numbers.  The structure used
for this mixing is intended to frustrate computation of the inputs
from the outputs.  The structure is also designed to mix the effects
of each bit of the input (both the ciphertext and key sections) so
that changing one bit of the input changes an average of about half
of the bits of the output.  This is sometimes called the avalanche
effect.

The Ruby cipher has not yet been fully analyzed for resistance to
cryptanalytic attacks, but was designed with a knowledge of how
several of these attacks work.  The best attack on this cipher might
well be better than a brute force attack on the 64 bit key, but since
some of the more obscure attacks require large quantities of cipher
text encrypted with the same key, I recommend that you use this
cipher in a way that uses a different session key to encrypt each
file or message, even if you use one master key to encrypt the
session keys.

The primary uses intended for the Ruby cipher are authentication and
encryption in embedded applications (such as tape drives) and in
software such as backup programs and secure communications
applications where high speed, small size, and efficient
implementations on 32-bit computer architectures are very important
considerations.

In the following function, P is the Plain text input, K is the Key,
and C is the Cipher text output.

*/

void ruby_crypt(unsigned char *P, unsigned char *K, unsigned char *C);

/*

The following hash functions are NOT intended for use in digital
signature applications, since the block size for Ruby is too short
for that.  They are convenient for reducing a longer passphrase (or
passphrase + salt) to a Ruby key of 64 bits.

*/

void ruby_hash_init(void);
void ruby_hash_update(unsigned char *b, unsigned count = 1);
void ruby_hash_final(unsigned char *hash);

