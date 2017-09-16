From pcl@foo.oucs.ox.ac.uk Wed Sep 21 16:40:30 CDT 1994
Article: 26282 of sci.crypt
Xref: chinet sci.crypt:26282 alt.security.pgp:16766
Newsgroups: sci.crypt,alt.security.pgp
Path: chinet!pagesat.net!pagesat.net!decwrl!pa.dec.com!jac.zko.dec.com!crl.dec.com!crl.dec.com!bloom-beacon.mit.edu!spool.mu.edu!howland.reston.ans.net!EU.net!uknet!comlab.ox.ac.uk!pcl
From: pcl@foo.oucs.ox.ac.uk (Paul C Leyland)
Subject: crypt(3) based encryption -- source code
Message-ID: <PCL.94Sep21154436@foo.oucs.ox.ac.uk>
Date: 21 Sep 1994 14:44:34 GMT
Lines: 153

/*

   This code may be freely copied and used for whatever purpose you
see fit.  It would be nice if my authorship was acknowledged, but I
don't insist on it.  I give absolutely no guarantee whatsoever that
this code is useful for anything whatsoever, and take no
responsibility for whatever happens, if anything.  I'd appreciate
hearing about bugs, but whinges about my coding style will be ignored.

Justification for writing this code: I got heartily sick of claims
>from  alt.security.pgp, from sci.crypt, from computer suppliers and
elsewhere, that crypt(3) was useless for encryption and was therefore
exportable from the US under ITAR.  Although the conclusion is valid,
the premise is not.  Note that I am physically located in the UK,
using software exported by DEC, a US company.  The code below shows
how crypt(3) can be used relatively easily to provide reasonably
strong general-purpose encryption with exportable code.  Relatively
easily means that I took less than 3 hours from a blank piece of disk
to a compilable and apparently working product.

Unfortunately, the encryption below is rather slower than pure DES,
over 25 times slower, but it is probably more secure in that the key
space is marginally greater and special-purpose hardware has not
(yet!) been built to implement a key-search engine.

Several other methods of exploiting crypt(3) are possible; this is
just one of many approaches.

Paul Leyland, pcl@ox.ac.uk, 21 September 1994

*/

#include <unistd.h>

static unsigned char keystream[8];
static unsigned char counter[10];
static int stream_ptr = 7;
static char itoa64[] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
static char a64toi[] = 
{
   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
   0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1,
   2,  3,  4,  5,  6,  7,  8,  9, 10, 11,  0,  0,  0,  0,  0,  0,
   0, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
  27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37,  0,  0,  0,  0,  0,
   0, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52,
  53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63
};


/*
   Here comes a tricky bit, so pay attention.  Because of ITAR, we
   can assume that crypt(3) is available, but no other interface to
   DES.  Life would be easy if crypt() took eight 8-bit characters and
   2 6-bit characters as arguments for the key and salt respectively.
   Unfortunately, some implementations of crypt stop reading key when
   they encounter a NULL.  Therefore, we have to use radix 255
   rather than 256, so as to avoid NULL.  A cheap alternative would be
   to force the high-bit on, but this reduces our key space too much.

*/

/* Radix 255 increment */
static void inc_counter ()
{
   int i=0, ncarry;

   while (i < 10)
   {
      ncarry = ++counter[i];
      if (ncarry) break;
      ++counter[i++];
   }
}   

/* Generate the next byte of key stream. */

static char next_byte ()
{
   unsigned char salt[3], password[9], ascii_stream[14], *encp;
   unsigned _24bits;

   if (stream_ptr < 7) return keystream[++stream_ptr];

   salt[0] = itoa64[(counter[8] >> 1) & 0x3f];
   salt[1] = itoa64[(counter[9] >> 1) & 0x3f];
   salt[2] = '\0';

   memcpy (password, counter, 8);
   password[9] = '\0';
   strcpy (ascii_stream, crypt (password, salt));
   inc_counter ();
   
   encp = ascii_stream + 2;	/* Step over salt */

/* Unpack radix-64 to 8-bit data */

   _24bits  = a64toi[*encp++] << 26;   _24bits >>= 6;
   _24bits |= a64toi[*encp++] << 26;   _24bits >>= 6;
   _24bits |= a64toi[*encp++] << 26;   _24bits >>= 6;
   _24bits |= a64toi[*encp++] << 26;

   keystream[0] = _24bits >> 24;
   keystream[1] = _24bits >> 16;
   keystream[2] = _24bits >> 8;

   _24bits  = a64toi[*encp++] << 26;   _24bits >>= 6;
   _24bits |= a64toi[*encp++] << 26;   _24bits >>= 6;
   _24bits |= a64toi[*encp++] << 26;   _24bits >>= 6;
   _24bits |= a64toi[*encp++] << 26;
   
   keystream[3] = _24bits >> 24;
   keystream[4] = _24bits >> 16;
   keystream[5] = _24bits >> 8;

   _24bits  = a64toi[*encp++] << 28;   _24bits >>= 6;
   _24bits |= a64toi[*encp++] << 26;   _24bits >>= 6;
   _24bits |= a64toi[*encp] << 26;
   
   keystream[6] = _24bits >> 24;
   keystream[7] = _24bits >> 16;

   return keystream[stream_ptr=0];
}

extern void csetkey (unsigned char *key)
{
   int i;
   for (i = 0; i < 10; i++) counter[i] = key[i];
   for (i = 0; i < 9; i++)
      if (counter[i] == 0)
      {
	 counter[i]++;
	 counter[i+1]++;
      }
      
   if (counter[9] == 0) counter[9] = 1;
}


/* Encrypt in place the data in block of length len bytes */

extern void ccrypt (char *block, int len)
{
   while (len--) *block++ ^= next_byte ();
}
--
Paul Leyland <pcl@black.ox.ac.uk>        | Hanging on in quiet desperation is
Oxford University Computing Services     |     the English way.
13 Banbury Road, Oxford, OX2 6NN, UK     | The time is gone, the song is over.
Tel: +44-865-273200  Fax: +44-865-273275 | Thought I'd something more to say.
Finger pcl@black.ox.ac.uk for PGP key    |


