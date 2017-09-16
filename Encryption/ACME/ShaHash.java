// ShaHash - the Secure Hash Algorithm
//
// Copyright (C) 1996 by Jef Poskanzer <jef@acme.com>.  All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
// OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
// SUCH DAMAGE.
//
// Visit the ACME Labs Java page for up-to-date versions of this and other
// fine Java utilities: http://www.acme.com/java/

package Acme.Crypto;

import java.io.*;

/// The Secure Hash Algorithm.
// <P>
// This is surprisingly fast, processing 28000 bytes per second on a
// SPARC Ultra.
// <P>
// <A HREF="/resources/classes/Acme/Crypto/ShaHash.java">Fetch the software.</A><BR>
// <A HREF="/resources/classes/Acme.tar.Z">Fetch the entire Acme package.</A>

public class ShaHash extends Hash
    {

    /// Constructor.
    public ShaHash()
	{
	super( SHA_DIGESTSIZE );
	reset();
	}

    /// Initialize (reset) the hash.
    public void reset()
	{
	shaInit();
	}

    /// Add a byte to the hash.
    public void add( byte b )
	{
	// Just use the block add routine.  Maybe add a buffer later.
	byte[] data = new byte[1];
	data[0] = b;
	add( data, 0, 1 );
	}

    /// Add some bytes to the hash.
    public void add( byte[] data, int off, int len )
	{
	shaUpdate( data, off, len );
	}
    
    /// Prepare the hash bytes for use.
    protected void prepare()
	{
	shaFinal();
	spreadIntsToBytes( digest, 0, hashBytes, 0, SHA_DIGESTSIZE/4 );
	}

    private static final boolean USE_MODIFIED_SHA = true;
    private static final int SHA_BLOCKSIZE = 64;
    private static final int SHA_DIGESTSIZE = 20;

    private int[] digest = new int[SHA_DIGESTSIZE/4];	// message digest
    private long bitCount;    				// 64-bit bit count
    private byte[] dataB = new byte[SHA_BLOCKSIZE];	// SHA byte data buffer
    private int[] dataI = new int[SHA_BLOCKSIZE/4];	// SHA long data buffer

    // This implementation includes a change to the algorithm introduced by
    // NIST at the behest of the NSA.  It supposedly corrects a weakness in
    // the original formulation.  Bruce Schneier described it thus in a
    // posting to the Cypherpunks mailing list on June 21, 1994 (as told to
    // us by Steve Bellovin):
    //
    //	This is the fix to the Secure Hash Standard, NIST FIPS PUB 180:
    //
    //	     In Section 7 of FIPS 180 (page 9), the line which reads
    //
    //	     "b) For t=16 to 79 let Wt = Wt-3 XOR Wt-8 XOR Wt-14 XOR
    //	     Wt-16."
    //
    //	     is to be replaced by
    //
    //	     "b) For t=16 to 79 let Wt = S1(Wt-3 XOR Wt-8 XOR Wt-14 XOR
    //	     Wt-16)."
    //
    //	     where S1 is a left circular shift by one bit as defined in
    //	     Section 3 of FIPS 180 (page 6):
    //
    //	     S1(X) = (X<<1) OR (X>>31).

    // The SHA f()-functions

    // Rounds 0-19.
    private static int f1( int x, int y, int z )
	{
	return ( x & y ) | ( ~x & z );
	}

    // Rounds 20-39.
    private static int f2( int x, int y, int z )
	{
	return x ^ y ^ z;
	}

    // Rounds 40-59.
    private static int f3( int x, int y, int z )
	{
	return ( x & y ) | ( x & z ) | ( y & z );
	}

    // Rounds 60-79.
    private static int f4( int x, int y, int z )
	{
	return x ^ y ^ z;
	}

    // The SHA Mysterious Constants.
    private static final int K1 = 0x5a827999;     // rounds  0-19
    private static final int K2 = 0x6ed9eba1;     // rounds 20-39
    private static final int K3 = 0x8f1bbcdc;     // rounds 40-59
    private static final int K4 = 0xca62c1d6;     // rounds 60-79

    // SHA initial values.
    private static final int h0init = 0x67452301;
    private static final int h1init = 0xefcdab89;
    private static final int h2init = 0x98badcfe;
    private static final int h3init = 0x10325476;
    private static final int h4init = 0xc3d2e1f0;

    // 32-bit left rotate - kludged with shifts.
    private static int rotateL( int x, int n )
	{
	return ( x << n ) | ( x >>> ( 32 - n ) );
	}


    // The four SHA sub-rounds.

    private void subRound1( int count )
	{
	int temp = rotateL( A, 5 ) + f1( B, C, D ) + E + W[count] + K1;
	E = D;
	D = C;
	C = rotateL( B, 30 );
	B = A;
	A = temp;
	}

    private void subRound2( int count )
	{
	int temp = rotateL( A, 5 ) + f2( B, C, D ) + E + W[count] + K2;
	E = D;
	D = C;
	C = rotateL( B, 30 );
	B = A;
	A = temp;
	}

    private void subRound3( int count )
	{
	int temp = rotateL( A, 5 ) + f3( B, C, D ) + E + W[count] + K3;
	E = D;
	D = C;
	C = rotateL( B, 30 );
	B = A;
	A = temp;
	}

    private void subRound4( int count )
	{
	int temp = rotateL( A, 5 ) + f4( B, C, D ) + E + W[count] + K4;
	E = D;
	D = C;
	C = rotateL( B, 30 );
	B = A;
	A = temp;
	}

    // The two buffers of 5 32-bit words.
    private int h0, h1, h2, h3, h4;
    private int A, B, C, D, E;

    /// Initialize the SHA values.
    private void shaInit()
	{
	// Set the h-vars to their initial values.
	digest[0] = h0init;
	digest[1] = h1init;
	digest[2] = h2init;
	digest[3] = h3init;
	digest[4] = h4init;

	// Initialise bit count.
	bitCount = 0;
	}

    private int[] W = new int[80];

    /// Perform the SHA transformation.
    private void shaTransform()
	{
	int i;

	// Step A.  Copy the data buffer into the local work buffer.
	for( i = 0; i < SHA_BLOCKSIZE/4; ++i )
	    W[i] = dataI[i];

	// Step B.  Expand the 16 words into 64 temporary data words.
	for ( ; i < 80; ++i )
	    {
	    W[i] = W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16];
	    if ( USE_MODIFIED_SHA )
		W[i] = rotateL( W[i], 1 );
	    }

	// Step C.  Set up first buffer
	A = digest[0];
	B = digest[1];
	C = digest[2];
	D = digest[3];
	E = digest[4];

	// Step D.  Serious mangling, divided into four sub-rounds.
	for ( i = 0; i < 20; ++i )
	    subRound1( i );
	for ( ; i < 40; ++i )
	    subRound2( i );
	for ( ; i < 60; ++i )
	    subRound3( i );
	for ( ; i < 80; ++i )
	    subRound4( i );

	// Step E.  Build message digest.
	digest[0] += A;
	digest[1] += B;
	digest[2] += C;
	digest[3] += D;
	digest[4] += E;
	}

    /// Update SHA for a block of data.  This code assumes that the buffer size
    // is a multiple of SHA_BLOCKSIZE bytes long, which makes the code a lot
    // more efficient since it does away with the need to handle partial blocks
    // between calls to shaUpdate().
    private void shaUpdate( byte[] buffer, int offset, int count )
	{
	// Update bitcount.
	bitCount += count << 3;

	// Process data in SHA_BLOCKSIZE chunks.
	while ( count >= SHA_BLOCKSIZE )
	    {
	    copyBlock( buffer, offset, dataB, 0, SHA_BLOCKSIZE );
	    squashBytesToInts( dataB, 0, dataI, 0, SHA_BLOCKSIZE/4 );
	    shaTransform();
	    offset += SHA_BLOCKSIZE;
	    count -= SHA_BLOCKSIZE;
	    }

	// Handle any remaining bytes of data.  This should only happen once
	// on the final lot of data.
	copyBlock( buffer, offset, dataB, 0, count );
	}

    private void shaFinal()
	{
	int count;

	// Compute number of bytes mod 64.
	count = (int) ( bitCount >>> 3 ) & 0x3F;

	// Set the first char of padding to 0x80.  This is safe since there is
	// always at least one byte free.
	dataB[count++] = (byte) 0x80;

	// Pad out to 56 mod 64.
	if ( count > SHA_BLOCKSIZE - 8 )
	    {
	    // Two lots of padding:  Pad the first block to 64 bytes.
	    fillBlock( dataB, count, (byte) 0, SHA_BLOCKSIZE - count );
	    squashBytesToInts( dataB, 0, dataI, 0, SHA_BLOCKSIZE/4 );
	    shaTransform();

	    // Now fill the next block with 56 bytes.
	    fillBlock( dataB, 0, (byte) 0, SHA_BLOCKSIZE - 8 );
	    }
	else
	    // Pad block to 56 bytes.
	    fillBlock( dataB, count, (byte) 0, SHA_BLOCKSIZE - 8 - count );
	squashBytesToInts( dataB, 0, dataI, 0, SHA_BLOCKSIZE/4 );

	// Append length in bits and transform.
	dataI[14] = (int) ( bitCount >>> 32 );
	dataI[15] = (int) ( bitCount & 0xffffffff );

	shaTransform();
	}


    // ----------------------------- SHA Test code ---------------------------

    // Size of buffer for SHA speed test data.
    private static int TEST_BLOCK_SIZE = SHA_DIGESTSIZE * 100;

    // Number of bytes of test data to process.
    private static int TEST_BYTES = 10000000;
    private static int TEST_BLOCKS = TEST_BYTES / TEST_BLOCK_SIZE;

    public static void main( String[] args )
	{
	ShaHash h = new ShaHash();

	// Test output data (this is the only test data given in the SHA
	// document, but chances are if it works for this it'll work for
	// anything).
	h.addASCII( "abc" );
	byte[] hb = h.get();
	byte[] oldCorrect = {
	    (byte) 0x01, (byte) 0x64, (byte) 0xb8, (byte) 0xa9,
	    (byte) 0x14, (byte) 0xcd, (byte) 0x2a, (byte) 0x5e,
	    (byte) 0x74, (byte) 0xc4, (byte) 0xf7, (byte) 0xff,
	    (byte) 0x08, (byte) 0x2c, (byte) 0x4d, (byte) 0x97,
	    (byte) 0xf1, (byte) 0xed, (byte) 0xf8, (byte) 0x80
	    };
	byte[] newCorrect = {
	    (byte) 0xa9, (byte) 0x99, (byte) 0x3e, (byte) 0x36,
	    (byte) 0x47, (byte) 0x06, (byte) 0x81, (byte) 0x6a,
	    (byte) 0xba, (byte) 0x3e, (byte) 0x25, (byte) 0x71,
	    (byte) 0x78, (byte) 0x50, (byte) 0xc2, (byte) 0x6c,
	    (byte) 0x9c, (byte) 0xd0, (byte) 0xd8, (byte) 0x9d
	    };
	byte[] correct;
	if ( USE_MODIFIED_SHA )
	    correct = newCorrect;
	else
	    correct = oldCorrect;
	System.out.println( "Got:  " + toStringBlock( hb ) );
	System.out.println( "Want: " + toStringBlock( correct ) );
	if ( ! equalsBlock( hb, correct ) )
	    {
	    System.err.println( "Error in SHA implementation." );
	    System.exit( 1 );
	    }

	// Now perform time trial, generating MD for 10MB of data.  First,
	// initialize the test data.
	byte[] data = new byte[TEST_BLOCK_SIZE];
	int i;

	fillBlock( data, (byte) 0 );

	System.out.println( "SHA time trial.  Processing " + TEST_BYTES + " characters..." );

	// Calculate SHA message digest in TEST_BLOCK_SIZE byte blocks.
	h.reset();
	for ( i = TEST_BLOCKS; i > 0; i-- )
	    h.add( data, 0, TEST_BLOCK_SIZE );
	h.get();

	System.out.println( "Done." );

	}

    }
