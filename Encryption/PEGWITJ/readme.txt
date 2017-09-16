Pegwit in Java version 1.0
==========================

This is a conversion into Java of George Barwood <george.barwood@dial.pipex.com>'s
Pegwit public key encryption program, based off version 8 of that original.

The code is all 100% Public Domain where I, Mr. Tines <tines@windsong.demon.co.uk>
am able to grant it.  To the best of my knowledge, all the inputs to this effort
were, and I feel obliged to maintain that status.

All this code is supplied under the following condition:-

THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

Coding issues
=============

At version 1.0, this program has not been packaged or encapsulated - while most classes
have a notional 

//package UK.co.demon.windsong.tines.pegwit;

comment at their head, this bundling of everything into a single package is not an ideal
final state - the various cryptographic components should be packaged separately, and
abstracted into interfaces for Hash, Public Key, Symmetric Encryption or what have you.
Without such a final package state, separating classes and methods into public/normal/private
is not a useful exercise; so the classes are probably more open than they need be in a 
fully designed library.

Exceptions - especially I/O expections - have not been uniformly handled at this release.
Often they are swallowed at low level and some failed state bubbled up.  Were I doing
this from scratch, I'd let IOException be thrown up all the way to the user interface
level.


Source files:
=============

The source code has been partly developed under Borland C++ 5.0's Java IDE, and partly 
under Wordpad; the former uses 4-column tabs, the latter 8.  Hence the tabbing will look
ragged as spaces and tabs are mixed.

Elliptic curve support:
=======================

Vlpoint.java
A simple multiple precision integer class

Gfpoint.java
Points within the Galois Field

Ecparams.java
Parameters for the field GF(2^255) only.  More can be taken from the 
pegwit source distribution; as Java doesn't allow conditional
compilation, the current static approach wouldn't do for a multi-option
system.

Ecpoint.java
Points on the elliptic curve over the field

Ecsig.java
A pair of Vlpoints representing a signature

Eccrypt.java
Extends Vlpoint; using the encoding of Gfpoint and Ecpoint entities as multiple precision
integers, provides the crucial methods
	public Vlpoint makePublicKey ()
		// creates the corresponding public key (this=private key)
   	public Vlpoint[] encrypt(Vlpoint secret)
		// creates exchanged value as [0] and session key as [1] from
 		// a Vlpoint generated with good entropy (this=public key)
	public Vlpoint decrypt(Vlpoint message)
		// converts exchanged value to session key (this=private key)
	public void sign(Vlpoint k, Vlpoint digest, Ecsig sig)
		// given arbitrary k, and message digest, generate signature (this=private key)
	public boolean verify(Vlpoint digest, Ecsig sig)
		// given digest, verify signature (this=public key)

Message Digest
==============

SHA1.java
implements the well known hash.

Square Cypher
=============
This implementation is little-endian, in the manner that the
incoming byte stream is packed into 4-byte quantities.

Sqtab.java
Constants for the algorithm.

Sqblock.java
A 16-byte block from a bytestream.

SquareVec.java
The 4x4-byte quantity that is at the core of the algorithm.  All the cryptographic mixing
operations are methods of this class.

Square.java
Is the main class providing cypher operations.  It provides a number of constructors, 
	public Square(Sqblock s)
		// generate keyschedule from key s for encrypt and decrypt
   	public Square(Sqblock s, boolean both)
		// generate keyschedule from key s for encrypt, and decrypt if both is true
	public void encrypt(Sqblock buffer) 
		// encrypt a 16-byte buffer chunk of input, ordered as input
   	public void decrypt(Sqblock buffer)
		// decrypt.

SquareCts.java
Extends Square to provide CBC mode with cyphertext stealing.  Adds

	public void setIV(Sqblock iv)
		// set IV for next bufferload of encryption
   	public void encrypt(byte[] buffer, int l)
		// encrypt bytes from buffer[0] to buffer[l-1]
	public void decrypt(byte[] buffer, int l)
		// decrypt.

Note that the superclass encrypt and decrypt methods are not hidden.  This is a
misfeature of the current structure.

I/O support
===========

Base64Input.java
Base64Output.java

Extend Filter<In|Out>putStream to provide Base64 armouring support.  Input expects the 
filtered stream to be positioned at the start of the Base64 block, and will continue until
a = is detected;  Output allows header and footer information to be passed directly 
via the writeLiteral method added to the interface.

ASCIIInputStream.java

Models the mangling of line-end character(s) to '\n', and filtering of any EOF character
on 'C' ASCII input - as per fopen(filename, "r"), or from stdin.

Pegwit itself
=============

PegwitMsg.java
Some strings used by the other classes

PegwitPrng.java
Pegwit's pseudorandom number generation vis multiple hash.  There are some downright
peculiar behaviours here, as the comments indicate.


Pegwit.java
The key class for the various operation supported by the program
   	public static boolean position (DataInput f_inp)
		// positions to the start of a ###-delimited block
	public static String keygen(InputStream f_key, DataOutput f_out)
		// Public key generation from secret key stream input
   	public static int pkEncrypt(InputStream f_key, InputStream f_sec,
   							InputStream f_inp, OutputStream f_out)
		// public key encryption - public key, entropy source, plaintext, cyphertext
		// supplies headers if output is a Base64Output
	public static int pkDecrypt(InputStream f_key, InputStream f_in,
   							OutputStream f_out)
		// public key decryption - private key, cyphertext, plaintext
		// call position() first if required.
	public static int sign(InputStream f_key, InputStream f_in,
   						DataOutput f_out)
		// split signature - private key, message, signature
   	public static int verify(InputStream f_key, InputStream f_sig,
   			InputStream f_in)
		// split signature verification - public key, signature, message
   	public static int ckEncrypt(InputStream f_key, InputStream f_in,
   				OutputStream f_out) throws IOException
		// conventional encryption - key, plaintext, cyphertext
		// supplies headers if output is a Base64Output
	public static int ckDecrypt(InputStream f_key, InputStream f_in,
   				OutputStream f_out)
		// conventional decryption - key, cyphertext, plaintext
		// call position() first if required.
	public static String clearsign(InputStream f_key, DataInput f_in,
   						DataOutput f_out)
		// clearsignature - private key, message, signed message
   	public static int clearverify(InputStream f_key, DataInput f_in,
   						DataOutput f_out)
		// verification of clearsigned text - key, signed, message body
		// call position() first.
	public static InputStream get_Pubkey(InputStream f_key)
   	throws IOException
		// get input stream positioned to start of hex representation of 
		// public key, following the "pegwit v8 public key" string.  Allows
		// the public key to have been sectioned into {} delimited chunks
		// e.g. in .sig files

User Interface
==============

PegwitCLI.java 
Emulates the DOS command line interface of the original program.  Used as a proof-of-
concept and testbed.  version 1.1 will add a GUI, I promise.

Testing
=======

Harness.java
Performs tests on the elliptic curves and SHA1 to show that they are consistent.

test.bat (and the other test.*) files uses PegwitCLI to show backwards compatibility
with the original DOS program.
