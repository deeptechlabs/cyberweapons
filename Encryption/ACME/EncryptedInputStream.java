// EncryptedInputStream - an InputStream that supports encryption
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

/// An InputStream that supports encryption.
// <P>
// This class encapsulates a StreamCipher or BlockCipher as an InputStream.
// You set up your cipher, pass it and the underlying stream to the
// EncryptedInputStream constructor, and then read your cleartext from
// this stream.  It gets read from the underlying stream and decrypted.
// Encryption is done by an EncryptedOutputStream.
// <P>
// When used with a StreamCipher, no input protocol is necessary, each
// byte of ciphertext turns into one byte of cleartext.  When used with a
// BlockCipher it's more complicated.  First, the raw BlockCipher gets
// encapsulated into a CbcBlockCipher, which needs an initialization
// vector; so each encrypted stream automatically starts off with such
// a vector.  After that, the stream is a series of (block,bytecount)
// pairs.  Each block of ciphertext is read from the stream, decrypted
// into a block of cleartext, and then one more byte is read that says how
// many bytes in the block are valid.  Generally the bytecount will
// be equal to the block size, but it can be less if the stream gets
// flushed or closed on a partial block.
// <P>
// <A HREF="/resources/classes/Acme/Crypto/EncryptedInputStream.java">Fetch the software.</A><BR>
// <A HREF="/resources/classes/Acme.tar.Z">Fetch the entire Acme package.</A>
// <P>
// @see EncryptedOutputStream
// @see StreamCipher
// @see BlockCipher
// @see CbcBlockCipher

public class EncryptedInputStream extends FilterInputStream
    {

    // The basic block cipher to use.
    private BlockCipher blockCipher = null;

    // The stream cipher to use.
    private StreamCipher streamCipher = null;

    // The cipher to use.
    private Cipher cipher;

    // The CBC block cipher to use.
    private CbcBlockCipher cbcBlockCipher = null;

    // Number of bytes in a block.
    private int blockSize;

    // Number of bytes available for ciphertext in a block.
    private int cryptoSize;

    // Block of bytes to be decrypted.
    private byte[] cipherText;

    // Block of bytes that have been decrypted.
    private byte[] clearText;

    // How many valid bytes are in the cipherText block.
    private int byteCount;

    // How many decrypted bytes have been read.
    private int bytesRead;

    /// Constructor for block ciphers.
    // @param blockCipher The cipher to use, e.g. DesCipher, IdeaCipher
    // @param in The raw input stream that we will be decrypting.
    public EncryptedInputStream( BlockCipher blockCipher, InputStream in )
	{
	super( in );
	this.blockCipher = blockCipher;
	this.blockSize = blockCipher.blockSize();
	cbcBlockCipher = new CbcBlockCipher( blockCipher );
	this.cryptoSize = blockSize;
	cipherText = new byte[blockSize];
	clearText = new byte[blockSize];
	byteCount = 0;
	bytesRead = 0;
	this.cipher = blockCipher;
	}

    /// Constructor for stream ciphers.
    // @param streamCipher The cipher to use, e.g. Rc4Cipher, Rot13Cipher
    // @param in The raw input stream that we will be decrypting.
    public EncryptedInputStream( StreamCipher streamCipher, InputStream in )
	{
	super( in );
	this.streamCipher = streamCipher;
	this.cipher = streamCipher;
	}
    

    private boolean inited = false;

    private void init() throws IOException
	{
	if ( ! inited )
	    {
	    inited = true;
	    // Read the IV from the stream and set it.
	    byte[] iv = new byte[blockSize];
	    int r = Acme.Utils.read( in, iv, 0, blockSize );
	    if ( r == -1 || r != blockSize )
		throw new IOException( "truncated initialization vector" );
	    cbcBlockCipher.setIv( iv );
	    }
	}
    

    /// Set the key.
    public void setKey( String keyStr )
	{
	cipher.setKey( keyStr );
	}


    // Whether we are currently decrypting input or not.
    private boolean decrypting = true;

    /// Decrypting can be enabled or disabled temporarily.
    public void setDecrypting( boolean decrypting ) throws IOException
	{
	if ( this.decrypting && ! decrypting )
	    {
	    // !!! do something about unread decrypted bytes?
	    }
	this.decrypting = decrypting;
	}


    // Read an encrypted block.  Returns -1 on EOF.
    private int getBlock() throws IOException
	{
	int r = Acme.Utils.read( in, cipherText, 0, blockSize );
	if ( r == -1 )
	    return -1;
	if ( r != blockSize )
	    throw new IOException( "truncated ciphertext block" );
	// Decrypt the block.
	cbcBlockCipher.decrypt( cipherText, 0, clearText, 0 );
	// Get the byte count.
	byteCount = in.read();
	if ( byteCount == -1 )
	    throw new IOException( "missing ciphertext bytecount" );
	if ( byteCount == 0 || byteCount > cryptoSize )
	    throw new IOException( "invalid ciphertext bytecount" );
	bytesRead = 0;
	return byteCount;
	}

    /// Read a byte of data.
    // @return -1 on EOF.
    public int read() throws IOException
	{
	init();
	if ( decrypting )
	    {
	    if ( blockCipher != null )
		{
		if ( bytesRead >= byteCount )
		    if ( getBlock() == -1 )
			return -1;
		return clearText[bytesRead++] & 0xff;
		}
	    else
		{
		// Stream cipher.
		int r = in.read();
		if ( r == -1 )
		    return -1;
		return streamCipher.decrypt( (byte) r ) & 0xff;
		}
	    }
	else
	    // Not decrypting.
	    return in.read();
	}

    /// Read into an array of bytes.  This is a fixed version
    // of java.io.InputStream.read(byte[], int, int).  The
    // standard version catches and ignores IOExceptions from
    // below; this version sends them on to the caller.
    public int read( byte[] b, int off, int len ) throws IOException
	{
	init();
	if ( decrypting )
	    {
	    if ( blockCipher != null )
		// It would be tricky to optimize this to decrypt whole blocks.
		return Acme.Utils.read( this, b, off, len );
	    else
		{
		// Stream cipher.
		byte[] cipherText = new byte[len];
		int r = Acme.Utils.read( in, cipherText, 0, len );
		if ( r == -1 )
		    return -1;
		streamCipher.decrypt( cipherText, 0, b, off, r );
		return r;
		}
	    }
	else
	    // Not decrypting.
	    return Acme.Utils.read( in, b, off, len );
	}

    }
