// Cipher - an encryption template
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

/// An encryption template.
// <P>
// <A HREF="/resources/classes/Acme/Crypto/Cipher.java">Fetch the software.</A><BR>
// <A HREF="/resources/classes/Acme.tar.Z">Fetch the entire Acme package.</A>
// <P>
// @see StreamCipher
// @see BlockCipher
// @see EncryptedOutputStream
// @see EncryptedInputStream

public abstract class Cipher extends CryptoUtils
    {

    /// Constructor.
    public Cipher( int keySize )
	{
	this.keySize = keySize;
	}

    /// How big a key is.  Keyless ciphers use 0.  Variable-length-key ciphers
    // also use 0.
    public int keySize;

    /// Return how big a key is.
    public int keySize()
	{
	return keySize;
	}

    /// Set the key from a block of bytes.
    public abstract void setKey( byte[] key );


    // Utility routines.

    /// Utility routine to set the key from a string.
    public void setKey( String keyStr )
	{
	setKey( makeKey( keyStr ) );
	}

    /// Utility routine to turn a string into a key of the right length.
    public byte[] makeKey( String keyStr )
	{
        byte[] key;
	if ( keySize == 0 )
	    key = new byte[keyStr.length()];
	else
	    key = new byte[keySize];
        int i, j;

        for ( j = 0; j < key.length; ++j )
            key[j] = 0;

        for ( i = 0, j = 0; i < keyStr.length(); ++i, j = (j+1) % key.length )
            key[j] ^= (byte) keyStr.charAt( i );

	return key;
	}

    }
