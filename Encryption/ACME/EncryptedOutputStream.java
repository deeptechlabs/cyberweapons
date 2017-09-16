// EncryptedOutputStream - an OutputStream that supports encryption
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

/// An OutputStream that supports encryption.
// <P>
// This class encapsulates a StreamCipher or BlockCipher as an OutputStream.
// You set up your cipher, pass it and the underlying stream to the
// EncryptedOutputStream constructor, and then write your cleartext to
// this stream.  It gets encrypted and sent to the underlying stream.
// Decryption is done by an EncryptedInputStream.
// <P>
// When used with a StreamCipher, no output protocol is necessary, each
// byte of cleartext turns into one byte of ciphertext.  When used with a
// BlockCipher it's more complicated.  First, the raw BlockCipher gets
// encapsulated into a CbcBlockCipher, which needs an initialization
// vector; so each encrypted stream automatically starts off with such
// a vector.  After that, the stream is a series of (block,bytecount)
// pairs.  Each block of cleartext is encrypted into a block of ciphertext,
// sent to the stream, and then one more byte is sent that says how
// many bytes in the block are valid.  Generally the bytecount will
// be equal to the block size, but it can be less if the stream gets
// flushed or closed on a partial block.
// <P>
// <A HREF="/resources/classes/Acme/Crypto/EncryptedOutputStream.java">Fetch the software.</A><BR>
// <A HREF="/resources/classes/Acme.tar.Z">Fetch the entire Acme package.</A>
// <P>
// @see EncryptedInputStream
// @see StreamCipher
// @see BlockCipher
// @see CbcBlockCipher

public class EncryptedOutputStream extends FilterOutputStream
    {

    // The basic block cipher to use.
    private BlockCipher blockCipher = null;

    // The stream cipher to use.
    private StreamCipher streamCipher = null;

    // The cipher to use.
    private Cipher cipher;

    // The CBC block cipher to use.
    private CbcBlockCipher cbcBlockCipher;

    // Number of bytes in a block.
    private int blockSize;

    // Number of bytes available for ciphertext in a block.
    private int cryptoSize;

    // Block of bytes to be encrypted.
    private byte[] clearText;

    // Block of bytes that have been encrypted.
    private byte[] cipherText;

    // How many valid bytes are in the clearText block.
    private int byteCount;

    /// Constructor for block ciphers.
    // @param blockCipher The cipher to use, e.g. DesCipher, IdeaCipher
    // @param out The raw output stream that we will be encrypting to.
    public EncryptedOutputStream( BlockCipher blockCipher, OutputStream out ) throws IOException
	{
	super( out );
	this.blockCipher = blockCipher;
	this.blockSize = blockCipher.blockSize();
	cbcBlockCipher = new CbcBlockCipher( blockCipher );
	cryptoSize = blockSize;
	clearText = new byte[blockSize];
	cipherText = new byte[blockSize];
	byteCount = 0;
	this.cipher = blockCipher;
	// Set a random IV and send it.
	out.write( cbcBlockCipher.setRandomIv(), 0, blockSize );
	}

    /// Constructor for stream ciphers.
    // @param streamCipher The cipher to use, e.g. Rc4Cipher, Rot13Cipher
    // @param out The raw output stream that we will be encrypting to.
    public EncryptedOutputStream( StreamCipher streamCipher, OutputStream out )
	{
	super( out );
	this.streamCipher = streamCipher;
	this.blockSize = 1;
	this.cipher = streamCipher;
	}
    

    /// Set the key.
    public void setKey( String keyStr )
	{
	cipher.setKey( keyStr );
	}


    // Whether we are currently encrypting output or not.
    private boolean encrypting = true;

    /// Encrypting can be enabled or disabled temporarily.
    public void setEncrypting( boolean encrypting ) throws IOException
	{
	if ( this.encrypting && ! encrypting )
	    flush();
	this.encrypting = encrypting;
	}


    private void sendBlock() throws IOException
	{
	// Fill up the block with random bytes, if necessary.
	for ( int i = byteCount; i < cryptoSize; ++i )
	    clearText[i] = (byte) ( Math.random() * 256.0 );
	// Encrypt it.
	cbcBlockCipher.encrypt( clearText, 0, cipherText, 0 );
	// Send the block.
	out.write( cipherText, 0, blockSize );
	// Write out a count of valid bytes.
	out.write( (byte) byteCount );
	byteCount = 0;
	}

    /// Write a byte.
    public void write( int b ) throws IOException
	{
	if ( encrypting )
	    {
	    if ( blockCipher != null )
		{
		clearText[byteCount++] = (byte) b;
		if ( byteCount >= cryptoSize )
		    sendBlock();
		}
	    else
		// Stream cipher.
		out.write( streamCipher.encrypt( (byte) b ) );
	    }
	else
	    // Not encrypting.
	    out.write( b );
	}
    
    /// Write some bytes.
    public void write( byte b[], int off, int len ) throws IOException
	{
	if ( encrypting )
	    {
	    if ( blockCipher != null )
		{
		for ( int i = off; i < off + len; ++i )
		    {
		    clearText[byteCount++] = b[i];
		    if ( byteCount >= cryptoSize )
			sendBlock();
		    }
		}
	    else
		{
		// Stream cipher.
		byte[] cipherText = new byte[len];
		streamCipher.encrypt( b, off, cipherText, 0, len );
		out.write( cipherText, 0, len );
		}
	    }
	else
	    // Not encrypting.
	    out.write( b, off, len );
	}


    /// Flush the stream.  This will write any buffered output bytes.
    public void flush() throws IOException
	{
	if ( encrypting && blockCipher != null && byteCount != 0 )
	    sendBlock();
	out.flush();
	}

    }
