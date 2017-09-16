/*
 *   Karn encryption
 *	Based on Phil Karn, sci.crypt, 13 Feb 1992
 *	See also his comments from sci.crypt, 23 Mar 1992.
 *	The method is a variant of that described in
 *	Zheng, Matsumoto and Imai, Crypto 89.
 *	See also, "A New Class of Cryptosystems Based on
 *	Interconnection Networks" by
 *	michaelp@terpsichore.informatic.rwth-aachen.de
 *
 *	A method for turning a hash function, here MD5, into a fast
 *	secret-key encryption.
 *
 *	This does triple hashing with nondistinct keys.
 */

typedef unsigned long UINT4;

/* Initial values for MD5 Transform hash function */
static UINT4 ihash[4] = {
  0x67452301L, 0xefcdab89L, 0x98badcfeL, 0x10325476L };

/* MD5 hash function */
extern void Transform ();


/* Basic transform for Karn encryption.  Take two 16-byte
   half-buffers, two 48-byte keys (which must be distinct), and use
   the MD5 Transform algorithm to produce two 16-byte output
   half-buffers.

   This is reversible: If we get out1 and out2 from in1, in2, key1, key2,
   then we can get in2 and in1 from out2, out1, key1, key2.

   in1, in2, out1, and out2 should point to 16-byte buffers.
   By convention, in1 and in2 are two halves of a 32-byte input
   buffer, and out1 and out2 are two halves of a 32-byte output
   buffer.

   key1 and key2 should point to 48-byte buffers with different contents.
 */
void
karn (out1, out2, in1, in2, key1, key2)
UINT4 *out1, *out2, *in1, *in2, *key1, *key2;
{
	int	i;
	UINT4	buf[16];
	UINT4	hash[4];
	UINT4	temp[4];

	bcopy (ihash, hash, sizeof(hash));
	bcopy (in1, buf, 16);
	bcopy (key1, buf+4, 48);
	Transform (hash, buf);
	for (i=0; i<4; ++i)
		temp[i] = buf[i] = in2[i] ^ hash[i];
	bcopy (ihash, hash, sizeof(hash));
	bcopy (key2, buf+4, 48);
	Transform (hash, buf);
	for (i=0; i<4; ++i)
		out2[i] = buf[i] = in1[i] ^ hash[i];
	bcopy (ihash, hash, sizeof(hash));
	bcopy (key1, buf+4, 48);
	Transform (hash, buf);
	for (i=0; i<4; ++i)
		out1[i] = temp[i] ^ hash[i];
}
