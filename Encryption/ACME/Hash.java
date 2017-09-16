// Hash - a hash-function template
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

/// A hash-function template.
// <P>
// Hash functions are also known as message digests or checksums.
// The idea is to reduce an arbitrary-length stream of bytes down
// to a fixed size, useful for comparisons, security, whatever.
// <P>
// <A HREF="/resources/classes/Acme/Crypto/Hash.java">Fetch the software.</A><BR>
// <A HREF="/resources/classes/Acme.tar.Z">Fetch the entire Acme package.</A>
// <P>
// @see StreamCipher
// @see BlockCipher

public abstract class Hash extends CryptoUtils
    {

    /// How big a hash is.
    protected int hashSize;

    /// The hash bytes.
    protected byte[] hashBytes;

    /// Constructor.  All sub-class constructors should call reset().
    // We can't call it here because it would get called before the
    // sub-class's variable initializations.
    public Hash( int hashSize )
	{
	this.hashSize = hashSize;
	hashBytes = new byte[hashSize];
	}

    /// Return how big a hash is.
    public int hashSize()
	{
	return hashSize;
	}

    /// Initialize (reset) the hash.
    public abstract void reset();

    /// Add a byte to the hash.
    public abstract void add( byte b );

    /// Add some bytes to the hash.  Default version just calls add(byte)
    // repeatedly.  Can be overridden for efficiency.
    public void add( byte[] data, int off, int len )
	{
	for ( int i = off; i < off + len; ++i )
	    add( data[i] );
	}

    /// Prepare the hash bytes for use.  This is called by get() just
    // before returning the bytes, and by other routines such as equals() and
    // toString() before looking at the bytes.  The default implementation does
    // nothing, but if a subclass wants to store the hash in some
    // form other than a byte array, it should override this routine
    // and have if convert the hash to bytes and store in hashBytes.
    protected void prepare()
	{
	}

    /// Get the current hash.
    public byte[] get()
	{
	prepare();
	byte[] hb = new byte[hashSize];
	System.arraycopy( hashBytes, 0, hb, 0, hashSize );
	return hb;
	}


    // Utility add routines for other types of input.

    /// Add a String to the hash.
    public void add( String str )
	{
	int len = str.length();
	char[] data = new char[len];
	str.getChars( 0, len, data, 0 );
	for ( int i = 0; i < len; ++i )
	    add( data[i] );
	}

    /// Add a String to the hash, ignoring the high bytes of each char.
    public void addASCII( String str )
	{
	int len = str.length();
	byte[] data = new byte[len];
	str.getBytes( 0, len, data, 0 );
	add( data, 0, len );
	}

    /// Add a byte array to the hash.
    public void add( byte[] data )
	{
	add( data, 0, data.length );
	}

    /// Add a boolean to the hash.
    public void add( boolean b )
	{
	if ( b )
	    add( (byte) 1 );
	else
	    add( (byte) 0 );
	}

    /// Add a char to the hash.
    public void add( char c )
	{
	add( (byte) ( c >>> 8 ) );
	add( (byte) c );
	}

    /// Add a short to the hash.
    public void add( short s )
	{
	add( (byte) ( s >>> 8 ) );
	add( (byte) s );
	}

    /// Add an int to the hash.
    public void add( int i )
	{
	add( (byte) ( i >>> 24 ) );
	add( (byte) ( i >>> 16 ) );
	add( (byte) ( i >>>  8 ) );
	add( (byte) i );
	}

    /// Add a long to the hash.
    public void add( long l )
	{
	add( (byte) ( l >>> 56 ) );
	add( (byte) ( l >>> 48 ) );
	add( (byte) ( l >>> 40 ) );
	add( (byte) ( l >>> 32 ) );
	add( (byte) ( l >>> 24 ) );
	add( (byte) ( l >>> 16 ) );
	add( (byte) ( l >>>  8 ) );
	add( (byte) l );
	}

    /// Add a float to the hash.
    public void add( float f )
	{
	add( Float.floatToIntBits( f ) );
	}

    /// Add a double to the hash.
    public void add( double d )
	{
	add( Double.doubleToLongBits( d ) );
	}

    /// Add any Object to the hash.
    public void add( Object o )
	{
	add( o.toString() );
	}


    // Other utility routines.

    /// Static utility routine for hashing a String in one step.
    // Call like so:
    // <BLOCKQUOTE>
    // byte[] hash = SomeHash.hashStr( str, new SomeHash() );
    // </BLOCKQUOTE>
    public static byte[] hashStr( String str, Hash hash )
	{
	hash.add( str );
	return hash.get();
	}


    /// Check if two hashes are equal.
    public boolean equals( Hash otherHash )
	{
	if ( otherHash.hashSize != hashSize )
	    return false;
	otherHash.prepare();
	prepare();
	for ( int i = 0; i < hashSize; ++i )
	    if ( otherHash.hashBytes[i] != hashBytes[i] )
		return false;
	return true;
	}
    
    /// Compute a Java int hash code, for use with java.util.Hashtable.
    // A hash of a Hash.
    public int hashCode()
	{
	prepare();
	int code = 0, shift = 0;
	for ( int i = 0; i < hashSize; ++i )
	    {
	    code ^= hashBytes[i] << shift;
	    shift = ( shift + 8 ) % 32;
	    }
	return code;
	}
    
    /// Convert a Hash to a String representation.
    public String toString()
	{
	prepare();
	return toStringBlock( hashBytes, 0, hashSize );
	}

    }
