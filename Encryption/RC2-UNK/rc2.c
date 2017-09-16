/**********************************************************************\
* To commemorate the 1996 RSA Data Security Conference, the following  *
* code is released into the public domain by its author.  Prost!       *
*                                                                      *
* This cipher uses 16-bit words and little-endian byte ordering.       *
* I wonder which processor it was optimized for?                       *
*                                                                      *
* Thanks to CodeView, SoftIce, and D86 for helping bring this code to  *
* the public.                                                          *
\**********************************************************************/

#include <string.h>
#include <assert.h>

/**********************************************************************\
* Expand a variable-length user key (between 1 and 128 bytes) to a     *
* 64-short working rc2 key, of at most "bits" effective key bits.      *
* The effective key bits parameter looks like an export control hack.  *
* For normal use, it should always be set to 1024.  For convenience,   *
* zero is accepted as an alias for 1024.                               *
\**********************************************************************/

void rc2_keyschedule( unsigned short xkey[64],
                      const unsigned char *key,
                      unsigned len,
                      unsigned bits )
	{
	unsigned char x;
	unsigned i;
	/* 256-entry permutation table, probably derived somehow from pi */
	static const unsigned char permute[256] = {
	    217,120,249,196, 25,221,181,237, 40,233,253,121, 74,160,216,157,
	    198,126, 55,131, 43,118, 83,142, 98, 76,100,136, 68,139,251,162,
	     23,154, 89,245,135,179, 79, 19, 97, 69,109,141,  9,129,125, 50,
	    189,143, 64,235,134,183,123, 11,240,149, 33, 34, 92,107, 78,130,
	     84,214,101,147,206, 96,178, 28,115, 86,192, 20,167,140,241,220,
	     18,117,202, 31, 59,190,228,209, 66, 61,212, 48,163, 60,182, 38,
	    111,191, 14,218, 70,105,  7, 87, 39,242, 29,155,188,148, 67,  3,
	    248, 17,199,246,144,239, 62,231,  6,195,213, 47,200,102, 30,215,
	      8,232,234,222,128, 82,238,247,132,170,114,172, 53, 77,106, 42,
	    150, 26,210,113, 90, 21, 73,116, 75,159,208, 94,  4, 24,164,236,
	    194,224, 65,110, 15, 81,203,204, 36,145,175, 80,161,244,112, 57,
	    153,124, 58,133, 35,184,180,122,252,  2, 54, 91, 37, 85,151, 49,
	     45, 93,250,152,227,138,146,174,  5,223, 41, 16,103,108,186,201,
	    211,  0,230,207,225,158,168, 44, 99, 22,  1, 63, 88,226,137,169,
	     13, 56, 52, 27,171, 51,255,176,187, 72, 12, 95,185,177,205, 46,
	    197,243,219, 71,229,165,156,119, 10,166, 32,104,254,127,193,173
	};

	assert(len > 0 && len <= 128);
	assert(bits <= 1024);
	if (!bits)
		bits = 1024;

	memcpy(xkey, key, len);

	/* Phase 1: Expand input key to 128 bytes */
	if (len < 128) {
		i = 0;
		x = ((unsigned char *)xkey)[len-1];
		do {
			x = permute[(x + ((unsigned char *)xkey)[i++]) & 255];
			((unsigned char *)xkey)[len++] = x;
		} while (len < 128);
	}

	/* Phase 2 - reduce effective key size to "bits" */
	len = (bits+7) >> 3;
	i = 128-len;
	x = permute[((unsigned char *)xkey)[i] & (255 >> (7 & -bits))];
	((unsigned char *)xkey)[i] = x;

	while (i--) {
		x = permute[ x ^ ((unsigned char *)xkey)[i+len] ];
		((unsigned char *)xkey)[i] = x;
	}

	/* Phase 3 - copy to xkey in little-endian order */
	i = 63;
	do {
		xkey[i] =  ((unsigned char *)xkey)[2*i] +
		          (((unsigned char *)xkey)[2*i+1] << 8);
	} while (i--);
	}

/**********************************************************************\
* Encrypt an 8-byte block of plaintext using the given key.            *
\**********************************************************************/

void rc2_encrypt( const unsigned short xkey[64],
                  const unsigned char *plain,
                  unsigned char *cipher )
	{
	unsigned x76, x54, x32, x10, i;

	x76 = (plain[7] << 8) + plain[6];
	x54 = (plain[5] << 8) + plain[4];
	x32 = (plain[3] << 8) + plain[2];
	x10 = (plain[1] << 8) + plain[0];

	for (i = 0; i < 16; i++) {
		x10 += (x32 & ~x76) + (x54 & x76) + xkey[4*i+0];
		x10 = (x10 << 1) + (x10 >> 15 & 1);
		
		x32 += (x54 & ~x10) + (x76 & x10) + xkey[4*i+1];
		x32 = (x32 << 2) + (x32 >> 14 & 3);

		x54 += (x76 & ~x32) + (x10 & x32) + xkey[4*i+2];
		x54 = (x54 << 3) + (x54 >> 13 & 7);

		x76 += (x10 & ~x54) + (x32 & x54) + xkey[4*i+3];
		x76 = (x76 << 5) + (x76 >> 11 & 31);

		if (i == 4 || i == 10) {
			x10 += xkey[x76 & 63];
			x32 += xkey[x10 & 63];
			x54 += xkey[x32 & 63];
			x76 += xkey[x54 & 63];
		}
	}

	cipher[0] = (unsigned char)x10;
	cipher[1] = (unsigned char)(x10 >> 8);
	cipher[2] = (unsigned char)x32;
	cipher[3] = (unsigned char)(x32 >> 8);
	cipher[4] = (unsigned char)x54;
	cipher[5] = (unsigned char)(x54 >> 8);
	cipher[6] = (unsigned char)x76;
	cipher[7] = (unsigned char)(x76 >> 8);
	}

/**********************************************************************\
* Decrypt an 8-byte block of ciphertext using the given key.           *
\**********************************************************************/

void rc2_decrypt( const unsigned short xkey[64],
                  unsigned char *plain,
                  const unsigned char *cipher )
	{
	unsigned x76, x54, x32, x10, i;

	x76 = (cipher[7] << 8) + cipher[6];
	x54 = (cipher[5] << 8) + cipher[4];
	x32 = (cipher[3] << 8) + cipher[2];
	x10 = (cipher[1] << 8) + cipher[0];

	i = 15;
	do {
		x76 &= 65535;
		x76 = (x76 << 11) + (x76 >> 5);
		x76 -= (x10 & ~x54) + (x32 & x54) + xkey[4*i+3];

		x54 &= 65535;
		x54 = (x54 << 13) + (x54 >> 3);
		x54 -= (x76 & ~x32) + (x10 & x32) + xkey[4*i+2];
		
		x32 &= 65535;
		x32 = (x32 << 14) + (x32 >> 2);
		x32 -= (x54 & ~x10) + (x76 & x10) + xkey[4*i+1];

		x10 &= 65535;
		x10 = (x10 << 15) + (x10 >> 1);
		x10 -= (x32 & ~x76) + (x54 & x76) + xkey[4*i+0];

		if (i == 5 || i == 11) {
			x76 -= xkey[x54 & 63];
			x54 -= xkey[x32 & 63];
			x32 -= xkey[x10 & 63];
			x10 -= xkey[x76 & 63];
		}
	} while (i--);

	plain[0] = (unsigned char)x10;
	plain[1] = (unsigned char)(x10 >> 8);
	plain[2] = (unsigned char)x32;
	plain[3] = (unsigned char)(x32 >> 8);
	plain[4] = (unsigned char)x54;
	plain[5] = (unsigned char)(x54 >> 8);
	plain[6] = (unsigned char)x76;
	plain[7] = (unsigned char)(x76 >> 8);
	}

Path: dsi.unimi.it!news.IT.net!dish.news.pipex.net!pipex!tank.news.pipex.net!pipex!news.mathworks.com!newsfeed.internetmci.com!news-feed.mci.newscorp.com!news.delphi.com!usenet
From: John Kelsey <jmkelsey@delphi.com>
Newsgroups: sci.crypt
Subject: Re: RC2 source code
Date: Tue, 30 Jan 96 10:20:43 -0500
Organization: Delphi (info@delphi.com email, 800-695-4005 voice)
Lines: 131
Message-ID: <xdIqw-j.jmkelsey@delphi.com>
References: <4ek273$rbv@blackice.winternet.com> <DLzMBK.6uH@cix.compulink.co.uk>
NNTP-Posting-Host: bos1b.delphi.com
X-To: "Stephen Kapp" <skapp@cix.compulink.co.uk>

-----BEGIN PGP SIGNED MESSAGE-----

[ To: sci.crypt ## Date: 01/29/96 09:18 pm ##
  Subject: RC2 source code ]

>From: anon-remailer@utopia.hacktic.nl (Anonymous)
>Newsgroups: sci.crypt
>Subject: RC2 source code
>Date: 29 Jan 1996 06:38:04 +0100

This was interesting.  Is this another "S1," or another
"alleged-RC4?"  The whole thing looks pretty believeable, i.e., it
doesn't have any obviously dumb parts that I can see.

Note that alleged RC2's block encryption function looks an awful lot
like one round of MD5 performed on 16-bit sub-blocks, using the
bitwise selection function as the nonlinear function, and a
key-derived constant table.  Additionally, in rounds four and
eleven, there are four lookups into the expanded key array.

The encryption function could be rewritten as

for(i=0;i<16;i++){
     a = rotl(a + bsel(d,c,b) + *sk++, 1);
     b = rotl(b + bsel(a,d,c) + *sk++, 2);
     c = rotl(c + bsel(d,c,b) + *sk++, 3);
     d = rolt(d + bsel(c,b,a) + *sk++, 5);

     if((i==4)||(i==11)){
          a += xk[d&0x3f];
          b += xk[a&0x3f];
          c += xk[b&0x3f];
          d += xk[c&0x3f];
     }
}

If this is accurate, it may give us some insight into Rivest's
development of MD4 and MD5, which were radically different than MD2.
What are the dates on this?  Did Rivest do MD4 or RC2 first?  This
may be the first block cipher in the commercial/academic world to
use a UFN structure.  One interesting part of this is the use of the
subkey array as an S-box twice during the encryption process.  I'm
curious as to why this would be used only twice, rather than each
round, i.e.

a += bsel(b,c,d) + *sk++ + s[d&0x3f];

Sticking a very different internal transformation in may have been
an attempt to make iterative (i.e., differential) attacks harder,
since there's no longer a single round function through which you
can pass differential characteristics.  This depends upon when RC2
was developed and released.

Note that the claim that "RC2 is not an iterative block cipher"
seems to be based on the fact that it has two instances where a
different round function is thrown in.  (Essentially, it's actually
an 18-round cipher with two different round functions, one of which
is used only twice.)  This other round function isn't very
impressive, since it uses only six bits of the source block to
affect the target block.

A one-bit change in a randomly-distributed input block looks
look like it will propogate pretty quickly:  There's a roughly 0.5
probability that it doesn't make it through the bsel function.  If
it does, then there's about a 0.5 probability that it will cause a
change in the carry bit.  This happens four times per "round," so a
one-bit change should have about a 2^{-8} chance to make it through
one round as a one-bit change, and so about a 2^{-128} chance to
make it through all sixteen rounds, assuming no impact from either
of the two S-box lookups. Does this look right, or am I missing
something?  (This is a first approximation--if our bit is in the
high-order position anywhere, then it *can't* cause a carry bit, but
there's no obvious way to keep it there for long.)  By choosing the
input block, I can ensure that one-bit XOR difference makes it
through the first step or two, but that doesn't do too much for an
actual attack.

Other XOR differences can help with the first round or so, but stop
being helpful afterward.  It generally looks hard to prevent
diffusion by choosing other values, at least using XOR differences,
because each subblock is rotated a different amount in each round.
(The bits don't keep lining up.)

We can also try to do a differential attack based on subtraction
modulo 2^16, based partially on Tom Berson's attempt to
differentially attack MD5 using subtraction modulo 2^32.  This gets
complicated because of the rotations and the bit selection
operations, but it ought to be tried if it hasn't already.

The key scheduling is also interesting, and somewhat reminiscent of
MD2's internal operations.  Each expanded key byte after the first N
(where N is the number of bytes in the user's key) is determined by
two bytes--the previous expanded key byte, and the expanded key byte
N positions back.  This means that we probably don't get ideal
mixing of the key bytes in the early expanded key bytes, but it
isn't clear to me that there will be a lot of problems with
reasonable key lengths.  (Note that a reasonable key length would be
128 bits=16 bytes, and that it should come from the output of a good
one-way hash function.)  I wouldn't recommend using the key schedule
to hash passphrases, since long passphrases would leave us with many
very low-entropy subkey values.  In general, I think that really
large user keys will leave us vulnerable to a variety of related-key
attacks and other nasty stuff.  I'm a little curious as to the
purpose of phase 2 of the key schedule, but since it's only used
when a watered-down version of the algorithm is wanted (right?), I
haven't spent much time looking at it.

Does alleged RC2's key schedule use the same permutation table as
MD2 does?  For small systems, this might have been a reasonably nice
space savings.  (On the other hand, if you have a hash function
available at the same time, it makes sense to go ahead and use it in
your key schedule, which isn't done here.)

The algorithm looks like it will have reasonable performance on
16-bit machines like the 8086, which was almost certainly one of the
requirements for the algorithm, given the times it was used.

Comments?

   --John Kelsey, jmkelsey@delphi.com / kelsey@counterpane.com
 PGP 2.6 fingerprint = 4FE2 F421 100F BB0A 03D1 FE06 A435 7E36

-----BEGIN PGP SIGNATURE-----
Version: 2.6.2

iQCVAwUBMQ43Q0Hx57Ag8goBAQG0LQQAiohrNSPvKzSIJjMeWjrK/r7HZOWp0Mhg
zcq60rIyPMpsDnxuk7VlLrU2XBy0Aff4QpO8jORS3VFKtaLH5XJehc7WTZF+1En1
ux4prro+Gpvn99HToTqKa6igxlEGYShskoF/aBIkszZAg6m/P92BPyZ/PW3tnMtp
MoMcdNGcO0I=
=ttGl
-----END PGP SIGNATURE-----

Path: dsi.unimi.it!news.IT.net!dish.news.pipex.net!pipex!tube.news.pipex.net!pipex!lade.news.pipex.net!pipex!tank.news.pipex.net!pipex!news.mathworks.com!newsfeed.internetmci.com!news.exodus.net!aimnet.com!news2.aimnet.com!athena.mit.edu!baldwin
From: baldwin@chirality.rsa.com (Robert Baldwin)
Newsgroups: sci.crypt
Subject: RC2 source code
Date: 1 Feb 96 10:46:48
Organization: RSA Data Security, Inc.
Lines: 32
Message-ID: <BALDWIN.96Feb1104648@chirality.rsa.com>
References: <4ehmfs$6nq@utopia.hacktic.nl>
NNTP-Posting-Host: rsa.com
In-reply-to: anon-remailer@utopia.hacktic.nl's message of 29 Jan 1996 06:38:04 +0100


WARNING NOTICE

	It has recently come to the attention of RSA Data
Security, Inc. that certain of its confidential and
proprietary source code has been misappropriated and
disclosed.  Despite such unauthorized use and disclosure,
RSA Data Security reserves all intellectual property rights
in such source code under applicable law, including without
limitation trade secret and copyright protection.  In
particular, RSA Data Security's RC2 (TM) symmetric block
cipher source code has been illegally misappropriated and
published.  Please be advised that these acts, as well as
any retransmission or use of this source code, is a
violation of trade secret, copyright and various other state
and federal laws.  Any person or entity that acquires,
discloses or uses this information without authorization or
license to do so from RSA Data Security, Inc. is in
violation of such laws and subject to applicable criminal
and civil penalties, which may include monetary and punitive
damages, payment of RSA's attorneys fees and other equitable
relief.

	RSA Data Security considers misappropriation of its
intellectual property to be most serious.  Not only is this
act a violation of law, but its publication is yet another
abuse of the Internet.  RSA has begun an investigation and
will proceed with appropriate action against anyone found to
have violated its intellectual property rights.

	Anyone having information about the misappropriation
identified above is encouraged to contact RSA directly.

Path: dsi.unimi.it!news.IT.net!dish.news.pipex.net!pipex!tube.news.pipex.net!pipex!lade.news.pipex.net!pipex!tank.news.pipex.net!pipex!news.mathworks.com!newsfeed.internetmci.com!dimensional.com!winternet.com!news
From: schneier@parka.winternet.com (Bruce Schneier)
Newsgroups: sci.crypt
Subject: Re: RC2 Source Code - Legal Warning from RSADSI
Date: 2 Feb 1996 05:15:34 GMT
Organization: Winternet Corporation, Mpls, MN
Lines: 50
Message-ID: <4es6lm$ca2@blackice.winternet.com>
References: <BALDWIN.96Feb1105007@chirality.rsa.com>
NNTP-Posting-Host: parka.winternet.com

In article <BALDWIN.96Feb1105007@chirality.rsa.com>,
Robert Baldwin <baldwin@chirality.rsa.com> wrote:
>
>	It has recently come to the attention of RSA Data
>Security, Inc. that certain of its confidential and
>proprietary source code has been misappropriated and
>disclosed.  Despite such unauthorized use and disclosure,
>RSA Data Security reserves all intellectual property rights
>in such source code under applicable law, including without
>limitation trade secret and copyright protection. 

Does anyone think that they have any legal ground to stand
on?  How can something be a trade secret if it is freely
available all over the world?

> In
>particular, RSA Data Security's RC2 (TM) symmetric block
>cipher source code has been illegally misappropriated and
>published. 

Two things.  One, note that RSADSI has admitted it is RC2.
When RC4 was outed, RSADSI was careful never to say that it
_was_ RC4.  Two, can anyone check if RC2 is really a
registered trademark.  And while they are at it, can they
check RC4, RC5, MD2, MD4, and MD5.

>	RSA Data Security considers misappropriation of its
>intellectual property to be most serious.  Not only is this
>act a violation of law, but its publication is yet another
>abuse of the Internet.  RSA has begun an investigation and
>will proceed with appropriate action against anyone found to
>have violated its intellectual property rights.

Note that I have published RC4 is APPLIED CRYPTOGRAPHY, 2ND
EDITION, and my publisher has not heard a peep out of their
lawyers.

>	Anyone having information about the misappropriation
>identified above is encouraged to contact RSA directly.

Hell, I'm curious as well.  Post whatever information you 
have on the Internet.

Bruce

**************************************************************************
* Bruce Schneier              APPLIED CRYPTOGRAPHY, 2nd EDITION is
* Counterpane Systems         available.  For info on a 15%
* schneier@counterpane.com    discount offer, send me e-mail.
**************************************************************************


