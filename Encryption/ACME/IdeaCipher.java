// IdeaCipher - the IDEA encryption method
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

/// The IDEA encryption method.
// <P>
// The basic algorithm came from "Applied Cryptography", Bruce Schneier,
// ISBN 0-471-59756-2.
// <P>
// This is surprisingly fast, for pure Java.  On a SPARC 20, wrapped
// in Acme.Crypto.EncryptedOutputStream or Acme.Crypto.EncryptedInputStream,
// it does around 7500 bytes/second, slightly faster than Acme.Crypto.DesCipher.
// <P>
// The IDEA(tm) block cipher is covered by patents held by ETH and a
// Swiss company called Ascom-Tech AG.  The Swiss patent number is
// PCT/CH91/00117, the European patent number is EP 0 482 154 B1, and
// the U.S. patent number is US005214703.  IDEA(tm) is a trademark of
// Ascom-Tech AG.  There is no license fee required for noncommercial
// use.  Commercial users may obtain licensing details from Dieter
// Profos, Ascom Tech AG, Solothurn Lab, Postfach 151, 4502 Solothurn,
// Switzerland, Tel +41 65 242885, Fax +41 65 235761.
// <P>
// <A HREF="/resources/classes/Acme/Crypto/IdeaCipher.java">Fetch the software.</A><BR>
// <A HREF="/resources/classes/Acme.tar.Z">Fetch the entire Acme package.</A>
// <P>
// @see EncryptedOutputStream
// @see EncryptedInputStream

public class IdeaCipher extends BlockCipher
    {

    // Constructor, string key.
    public IdeaCipher( String keyStr )
	{
	super( 16, 8 );
	setKey( keyStr );
	}

    // Constructor, byte-array key.
    public IdeaCipher( byte[] key )
	{
	super( 16, 8 );
	setKey( key );
	}

    // Key routines.

    private int[] encryptKeys = new int[52];
    private int[] decryptKeys = new int[52];

    /// Set the key.
    public void setKey( byte[] key )
	{
	int k1, k2, j;
	int t1, t2, t3;

	// Encryption keys.  The first 8 key values come from the 16
	// user-supplied key bytes.
	for ( k1 = 0; k1 < 8; ++k1 )
	    encryptKeys[k1] =
		( ( key[2 * k1] & 0xff ) << 8 ) | ( key[ 2 * k1 + 1] & 0xff );

	// Subsequent key values are the previous values rotated to the
	// left by 25 bits.
	for ( ; k1 < 52; ++k1 )
	    encryptKeys[k1] =
		( ( encryptKeys[k1 - 8] << 9 ) |
		  ( encryptKeys[k1 - 7] >>> 7 ) ) & 0xffff;

	// Decryption keys.  These are the encryption keys, inverted and
	// in reverse order.
	k1 = 0;
	k2 = 51;
	t1 = mulinv( encryptKeys[k1++] );
	t2 = -encryptKeys[k1++];
	t3 = -encryptKeys[k1++];
	decryptKeys[k2--] = mulinv( encryptKeys[k1++] );
	decryptKeys[k2--] = t3;
	decryptKeys[k2--] = t2;
	decryptKeys[k2--] = t1;
	for ( j = 1; j < 8; ++j )
	    {
	    t1 = encryptKeys[k1++];
	    decryptKeys[k2--] = encryptKeys[k1++];
	    decryptKeys[k2--] = t1;
	    t1 = mulinv( encryptKeys[k1++] );
	    t2 = -encryptKeys[k1++];
	    t3 = -encryptKeys[k1++];
	    decryptKeys[k2--] = mulinv( encryptKeys[k1++] );
	    decryptKeys[k2--] = t2;
	    decryptKeys[k2--] = t3;
	    decryptKeys[k2--] = t1;
	    }
	t1 = encryptKeys[k1++];
	decryptKeys[k2--] = encryptKeys[k1++];
	decryptKeys[k2--] = t1;
	t1 = mulinv( encryptKeys[k1++] );
	t2 = -encryptKeys[k1++];
	t3 = -encryptKeys[k1++];
	decryptKeys[k2--] = mulinv( encryptKeys[k1++] );
	decryptKeys[k2--] = t3;
	decryptKeys[k2--] = t2;
	decryptKeys[k2--] = t1;
	}


    // Block encryption routines.

    private int[] tempShorts = new int[4];

    /// Encrypt a block of eight bytes.
    public void encrypt( byte[] clearText, int clearOff, byte[] cipherText, int cipherOff )
	{
	squashBytesToShorts( clearText, clearOff, tempShorts, 0, 4 );
	idea( tempShorts, tempShorts, encryptKeys );
	spreadShortsToBytes( tempShorts, 0, cipherText, cipherOff, 4 );
	}

    /// Decrypt a block of eight bytes.
    public void decrypt( byte[] cipherText, int cipherOff, byte[] clearText, int clearOff )
	{
	squashBytesToShorts( cipherText, cipherOff, tempShorts, 0, 4 );
	idea( tempShorts, tempShorts, decryptKeys );
	spreadShortsToBytes( tempShorts, 0, clearText, clearOff, 4 );
	}

    // Run IDEA on one block.
    private void idea( int[] inShorts, int[] outShorts, int[] keys )
	{
	int x1, x2, x3, x4, k, t1, t2;

	x1 = inShorts[0];
	x2 = inShorts[1];
	x3 = inShorts[2];
	x4 = inShorts[3];
	k = 0;
	for ( int round = 0; round < 8; ++round )
	    {
	    x1 = mul( x1 & 0xffff, keys[k++] );
	    x2 = x2 + keys[k++];
	    x3 = x3 + keys[k++];
	    x4 = mul( x4 & 0xffff, keys[k++] );
	    t2 = x1 ^ x3;
	    t2 = mul( t2 & 0xffff, keys[k++] );
	    t1 = t2 + ( x2 ^ x4 );
	    t1 = mul( t1 & 0xffff, keys[k++] );
	    t2 = t1 + t2;
	    x1 ^= t1;
	    x4 ^= t2;
	    t2 ^= x2;
	    x2 = x3 ^ t1;
	    x3 = t2;
	    }
	outShorts[0] = mul( x1 & 0xffff, keys[k++] ) & 0xffff;
	outShorts[1] = ( x3 + keys[k++] ) & 0xffff;
	outShorts[2] = ( x2 + keys[k++] ) & 0xffff;
	outShorts[3] = mul( x4 & 0xffff, keys[k++] ) & 0xffff;
	}

    // Multiplication modulo 65537.
    private static int mul( int a, int b )
	{
	int ab = a * b;
	if ( ab != 0 )
	    {
	    int lo = ab & 0xffff;
	    int hi = ab >>> 16;
	    return ( ( lo - hi ) + ( lo < hi ? 1 : 0 ) ) & 0xffff;
	    }
	if ( a != 0 )
	    return ( 1 - a ) & 0xffff;
	return ( 1 - b ) & 0xffff;
	}
    
    // The multiplicative inverse of x, modulo 65537.  Uses Euclid's
    // GCD algorithm.  It is unrolled twice to avoid swapping the
    // meaning of the registers each iteration, and some subtracts
    // of t have been changed to adds.
    private static int mulinv( int x )
	{
	int t0, t1, q, y;
	if ( x <= 1 )
	    return x;		// 0 and 1 are self-inverse
	t0 = 1;
	t1 = 0x10001 / x;	// since x >= 2, this fits into 16 bits
	y = ( 0x10001 % x ) & 0xffff;
	for (;;)
	    {
	    if ( y == 1 )
		return ( 1 - t1 ) & 0xffff;
	    q = x / y;
	    x = x % y;
	    t0 = ( t0 + q * t1 ) & 0xffff;
	    if ( x == 1 )
		return t0;
	    q = y / x;
	    y = y % x;
	    t1 = ( t1 + q * t0 ) & 0xffff;
	    }
	}


    /// Test routine.
    public static void main( String[] args )
	{
	// Check that mul and mulinv are working for all 16-bit numbers.
	for ( int a = 0; a < 65536; ++a )
	    {
	    int b = mulinv( a );
	    int c = mul( a, b );
	    if ( c != 1 )
		System.err.println( "mul/mulinv flaw: " + a + " * " + b + " = " + c );
	    }
	}

    }
