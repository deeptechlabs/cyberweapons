// NullCipher - the null encryption method
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

/// The null encryption method.
// <P>
// This is a block cipher that just copies input to output, unmodified.
// It's mostly for testing.  However, using the null cipher in CBC mode,
// for example via EncryptedOutputStream and EncryptedInputStream, turns
// out to hash things up enough to protect against casual inspection.
// There may be applications where this is appropriate.
// <P>
// <A HREF="/resources/classes/Acme/Crypto/NullCipher.java">Fetch the software.</A><BR>
// <A HREF="/resources/classes/Acme.tar.Z">Fetch the entire Acme package.</A>
// <P>
// @see EncryptedOutputStream
// @see EncryptedInputStream

public class NullCipher extends BlockCipher
    {

    /// Constructor.
    public NullCipher()
	{
	super( 0, 8 );
	}


    // Key routines.

    /// Set the key.  Null routine to avoid compilation error.
    public void setKey( byte[] key )
	{
	throw new InternalError( "NullCipher does not need a key" );
	}


    // Block encryption routines.

    /// "Encrypt" a block of eight bytes.
    public void encrypt( byte[] clearText, int clearOff, byte[] cipherText, int cipherOff )
	{
	copyBlock( clearText, clearOff, cipherText, cipherOff, blockSize );
	}

    /// "Decrypt" a block of eight bytes.
    public void decrypt( byte[] cipherText, int cipherOff, byte[] clearText, int clearOff )
	{
	copyBlock( cipherText, cipherOff, clearText, clearOff, blockSize );
	}

    }
