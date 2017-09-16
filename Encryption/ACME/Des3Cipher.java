// Des3Cipher - the triple-DES encryption method
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

/// The triple-DES encryption method.
// <P>
// This is a fairly standard way of increasing the security of DES.
// You run each block through DES three times, first encrypting with
// key A, then decrypting with key B, then encrypting again with key A
// again.
// <P>
// <A HREF="/resources/classes/Acme/Crypto/Des3Cipher.java">Fetch the software.</A><BR>
// <A HREF="/resources/classes/Acme.tar.Z">Fetch the entire Acme package.</A>
// <P>
// @see DesCipher
// @see EncryptedOutputStream
// @see EncryptedInputStream

public class Des3Cipher extends BlockCipher
    {

    /// Constructor, string key.
    public Des3Cipher( String keyStr )
	{
	super( 16, 8 );
	setKey( keyStr );
	}

    /// Constructor, byte-array key.
    public Des3Cipher( byte[] key )
	{
	super( 16, 8 );
	setKey( key );
	}


    // Key routines.

    private byte[] keyA = new byte[8];
    private byte[] keyB = new byte[8];

    private DesCipher desA;
    private DesCipher desB;

    /// Set the key.
    public void setKey( byte[] key )
	{
	System.arraycopy( key, 0, keyA, 0, 8 );
	System.arraycopy( key, 8, keyB, 0, 8 );
	desA = new DesCipher( keyA );
	desB = new DesCipher( keyB );
	}


    // Block encryption routines.

    byte[] temp1 = new byte[8];
    byte[] temp2 = new byte[8];

    /// Encrypt a block of eight bytes.
    public void encrypt( byte[] clearText, int clearOff, byte[] cipherText, int cipherOff )
	{
	desA.encrypt( clearText, clearOff, temp1, 0 );
	desB.decrypt( temp1, 0, temp2, 0 );
	desA.encrypt( temp2, 0, cipherText, cipherOff );
	}

    /// Decrypt a block of eight bytes.
    public void decrypt( byte[] cipherText, int cipherOff, byte[] clearText, int clearOff )
	{
	desA.decrypt( cipherText, cipherOff, temp1, 0 );
	desB.encrypt( temp1, 0, temp2, 0 );
	desA.decrypt( temp2, 0, clearText, clearOff );
	}

    }
