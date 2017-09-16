// cryptlib.h - written and placed in the public domain by Wei Dai

// This file contains the declarations for the abstract base
// classes that provide a uniform interface to this library.

#ifndef CRYPTOPP_CRYPTLIB_H
#define CRYPTOPP_CRYPTLIB_H

#include "config.h"
#include <exception>
#include <string>

NAMESPACE_BEGIN(CryptoPP)

/// base class for all exceptions thrown by Crypto++
class Exception : public std::exception
{
public:
	explicit Exception(const std::string& s) : m_what(s) {}
	virtual ~Exception() throw() {}
	const char *what() const throw() {return (m_what.c_str());}

private:
	std::string m_what;
};

/// used to specify a direction for a cipher to operate in (encrypt or decrypt)
enum CipherDir {
	///
	ENCRYPTION,
	///
	DECRYPTION};


/// abstract base class for block ciphers

/** All classes derived from BlockTransformation are block ciphers
	in ECB mode (for example the DESEncryption class), which are stateless.
	These classes should not be used directly, but only in combination with
	a mode class (see \Ref{CipherMode}).

	Note: BlockTransformation objects may assume that pointers to input and
	output blocks are aligned on 32-bit word boundaries.
*/
class BlockTransformation
{
public:
	///
	virtual ~BlockTransformation() {}

	/// encrypt or decrypt one block in place
	//* Precondition: size of inoutBlock == BlockSize().
	virtual void ProcessBlock(byte *inoutBlock) const =0;

	/// encrypt or decrypt one block, may assume inBlock != outBlock
	//* Precondition: size of inBlock and outBlock == BlockSize().
	virtual void ProcessBlock(const byte *inBlock, byte *outBlock) const =0;

	/// block size of the cipher in bytes
	virtual unsigned int BlockSize() const =0;
};


/// abstract base class for stream ciphers

class StreamCipher
{
public:
	///
	virtual ~StreamCipher() {}

	/// encrypt or decrypt one byte
	virtual byte ProcessByte(byte input) =0;

	/// encrypt or decrypt an array of bytes of specified length in place
	virtual void ProcessString(byte *inoutString, unsigned int length);
	/// encrypt or decrypt an array of bytes of specified length, may assume inString != outString
	virtual void ProcessString(byte *outString, const byte *inString, unsigned int length);
};

/// abstract base class for random access stream ciphers

class RandomAccessStreamCipher : public virtual StreamCipher
{
public:
	///
	virtual ~RandomAccessStreamCipher() {}
	/*/ specify that the next byte to be processed is at absolute position n
		in the plaintext/ciphertext stream */
	virtual void Seek(unsigned long n) =0;
};

/// abstract base class for random number generators
/** All return values are uniformly distributed over the range specified.
*/
class RandomNumberGenerator
{
public:
	///
	virtual ~RandomNumberGenerator() {}

	/// generate new random byte and return it
	virtual byte GetByte() =0;

	/// generate new random bit and return it
	/** Default implementation is to call GetByte() and return its parity. */
	virtual unsigned int GetBit();

	/// generate a random 32 bit word in the range min to max, inclusive
	virtual word32 GetLong(word32 a=0, word32 b=0xffffffffL);
	/// generate a random 16 bit word in the range min to max, inclusive
	virtual word16 GetShort(word16 a=0, word16 b=0xffff)
		{return (word16)GetLong(a, b);}

	/// generate random array of bytes
	//* Default implementation is to call GetByte size times.
	virtual void GetBlock(byte *output, unsigned int size);
};

/// randomly shuffle the specified array, resulting permutation is uniformly distributed
template <class IT> void RandomShuffle(RandomNumberGenerator &rng, IT begin, IT end)
{
	for (; begin != end; ++begin)
		std::iter_swap(begin, begin + rng.GetLong(0, end-begin-1));
}

/// abstract base class for hash functions
/** HashModule objects are stateful.  They are created in an initial state,
	change state as Update() is called, and return to the initial
	state when Final() is called.  This interface allows a large message to
	be hashed in pieces by calling Update() on each piece followed by
	calling Final().
*/
class HashModule
{
public:
	///
	virtual ~HashModule() {}

	/// process more input
	virtual void Update(const byte *input, unsigned int length) =0;

	/*/ calculate hash for the current message (the concatenation of all
		inputs passed in via Update()), then reinitialize the object */
	//* Precondition: size of digest == DigestSize().
	virtual void Final(byte *digest) =0;

	/// size of the hash returned by Final()
	virtual unsigned int DigestSize() const =0;

	/// use this if your input is short and you don't want to call Update() and Final() seperately
	virtual void CalculateDigest(byte *digest, const byte *input, int length)
		{Update(input, length); Final(digest);}

	/// verify that digest is a valid digest for the current message, then reinitialize the object
	/** Default implementation is to call Final() and do a bitwise comparison
		between its output and digest. */
	virtual bool Verify(const byte *digest);

	/// use this if your input is short and you don't want to call Update() and Verify() seperately
	virtual bool VerifyDigest(const byte *digest, const byte *input, int length)
		{Update(input, length); return Verify(digest);}
};

/// abstract base class for message authentication codes

/** The main differences between a MAC and an hash function (in terms of
	programmatic interface) is that a MAC is keyed, and that calculating
	a MAC for the same message twice may produce two different results so
	verifying a MAC may not be simply recalculating it and doing a bitwise
	comparison.
*/
class MessageAuthenticationCode : public virtual HashModule
{
public:
	///
	virtual ~MessageAuthenticationCode() {}
};

/// abstract base class for buffered transformations

/** BufferedTransformation is a generalization of \Ref{BlockTransformation},
	\Ref{StreamCipher}, and \Ref{HashModule}.

	A buffered transformation is an object that takes a stream of bytes
	as input (this may be done in stages), does some computation on them, and
	then places the result into an internal buffer for later retrieval.  Any
	partial result already in the output buffer is not modified by further
	input.

	Computation is generally done as soon as possible, but some buffering
	on the input may be done for performance reasons.
*/
class BufferedTransformation
{
public:
	///
	virtual ~BufferedTransformation() {}

	//@Man: INPUT
	//@{
		/// input a byte for processing
		virtual void Put(byte inByte) =0;
		/// input multiple bytes
		virtual void Put(const byte *inString, unsigned int length) =0;
		/// signal that no more input is available
		/** A user should call Close() instead since it
			will automaticly call InputFinish() for this and all
			attached objects
		*/
		virtual void InputFinished() {}

		/// input a 16-bit word, big-endian or little-endian depending on highFirst
		void PutShort(word16 value, bool highFirst=true);
		/// input a 32-bit word
		void PutLong(word32 value, bool highFirst=true);
	//@}

	//@Man: RETRIEVAL
	//@{
		/// returns number of bytes that is currently ready for retrieval
		/** All retrieval functions return the actual number of bytes
			retrieved, which is the lesser of the request number and
			MaxRetrieveable(). */
		virtual unsigned long MaxRetrieveable() =0;

		/// try to retrieve a single byte
		virtual unsigned int Get(byte &outByte) =0;
		/// try to retrieve multiple bytes
		virtual unsigned int Get(byte *outString, unsigned int getMax) =0;

		/// try to retrieve a 16-bit word, big-endian or little-endian depending on highFirst
		unsigned int GetShort(word16 &value, bool highFirst=true);
		/// try to retrieve a 32-bit word
		unsigned int GetLong(word32 &value, bool highFirst=true);

		/// move all of the buffered output to target as input
		virtual unsigned long TransferTo(BufferedTransformation &target);
		/// same as above but only transfer up to transferMax bytes
		virtual unsigned int TransferTo(BufferedTransformation &target, unsigned int transferMax);

		/// discard some bytes from the output buffer
		virtual unsigned int Skip(unsigned int skipMax);

		/// peek at the next byte without removing it from the output buffer
		virtual unsigned int Peek(byte &outByte) const =0;
		/// peek at multiple bytes without removing them from the output buffer
		virtual unsigned int Peek(byte *outString, unsigned int peekMax) const =0;

		/// copy all of the buffered output to target as input
		virtual unsigned long CopyTo(BufferedTransformation &target) const =0;
		/// same as above but only copy up to copyMax bytes
		virtual unsigned int CopyTo(BufferedTransformation &target, unsigned int copyMax) const =0;
	//@}

	//@Man: ATTACHMENT
	//@{
		/** Some BufferedTransformation objects (e.g. \Ref{Filter} objects)
			allow other BufferedTransformation objects to be attached. When
			this is done, the first object instead of buffering its output,
			sents that output to the attached object as input. The entire
			attachment chain is deleted when the anchor object is destructed.
		*/
		/// returns whether this object allows attachment
		virtual bool Attachable() {return false;}
		/// returns the object immediately attached to this object or NULL for no attachment
		virtual BufferedTransformation *AttachedTransformation() {return 0;}
		///
		virtual const BufferedTransformation *AttachedTransformation() const
			{return const_cast<BufferedTransformation *>(this)->AttachedTransformation();}
		/// delete the current attachment chain and replace it with newAttachment
		/** Close() and TransferTo(*newAttachment) will be called on 
			AttachedTransformation() first if it is not NULL.
		*/
		virtual void Detach(BufferedTransformation *newAttachment = 0) {}
		/// add newAttachment to the end of attachment chain
		virtual void Attach(BufferedTransformation *newAttachment) {}
		/// call InputFinished() for all attached objects
		virtual void Close() {InputFinished();}
	//@}
};

/// abstract base class for public-key encryptors and decryptors

/** This class provides an interface common to encryptors and decryptors
	for querying their plaintext and ciphertext lengths.
*/
class PK_CryptoSystem
{
public:
	///
	virtual ~PK_CryptoSystem() {}

	/// maximum length of plaintext for a given ciphertext length
	//* This function returns 0 if cipherTextLength is not valid (too long or too short).
	virtual unsigned int MaxPlainTextLength(unsigned int cipherTextLength) const =0;

	/// calculate length of ciphertext given length of plaintext
	//* This function returns 0 if plainTextLength is not valid (too long).
	virtual unsigned int CipherTextLength(unsigned int plainTextLength) const =0;
};

/// abstract base class for public-key encryptors

/** An encryptor is also a public encryption key.  It contains both the
	key and the algorithm to perform the encryption.
*/
class PK_Encryptor : public virtual PK_CryptoSystem
{
public:
	/// encrypt a byte string
	/** Preconditions:
			\begin{itemize}
			\item CipherTextLength(plainTextLength) != 0 (i.e., plainText isn't too long)
			\item size of cipherText == CipherTextLength(plainTextLength)
			\end{itemize}
	*/
	virtual void Encrypt(RandomNumberGenerator &rng, const byte *plainText, unsigned int plainTextLength, byte *cipherText) =0;
};

/// abstract base class for public-key decryptors

/** An decryptor is also a private decryption key.	It contains both the
	key and the algorithm to perform the decryption.
*/
class PK_Decryptor : public virtual PK_CryptoSystem
{
public:
	/// decrypt a byte string, and return the length of plaintext
	/** Precondition: size of plainText == MaxPlainTextLength(cipherTextLength)
		bytes.

		The function returns the actual length of the plaintext, or 0
		if decryption fails.
	*/
	virtual unsigned int Decrypt(const byte *cipherText, unsigned int cipherTextLength, byte *plainText) =0;
};

/// abstract base class for encryptors and decryptors with fixed length ciphertext

/** A simplified interface (as embodied in this
	class and its subclasses) is provided for crypto systems (such
	as RSA) whose ciphertext length depend only on the key, not on the length
	of the plaintext.  The maximum plaintext length also depend only on
	the key.
*/
class PK_FixedLengthCryptoSystem : public virtual PK_CryptoSystem
{
public:
	///
	virtual unsigned int MaxPlainTextLength() const =0;
	///
	virtual unsigned int CipherTextLength() const =0;

	unsigned int MaxPlainTextLength(unsigned int cipherTextLength) const;
	unsigned int CipherTextLength(unsigned int plainTextLength) const;
};

/// abstract base class for encryptors with fixed length ciphertext

class PK_FixedLengthEncryptor : public virtual PK_Encryptor, public virtual PK_FixedLengthCryptoSystem
{
};

/// abstract base class for decryptors with fixed length ciphertext

class PK_FixedLengthDecryptor : public virtual PK_Decryptor, public virtual PK_FixedLengthCryptoSystem
{
public:
	/// decrypt a byte string, and return the length of plaintext
	/** Preconditions:
			\begin{itemize}
			\item length of cipherText == CipherTextLength()
			\item size of plainText == MaxPlainTextLength()
			\end{itemize}

		The function returns the actual length of the plaintext, or 0
		if decryption fails.
	*/
	virtual unsigned int Decrypt(const byte *cipherText, byte *plainText) =0;

	unsigned int Decrypt(const byte *cipherText, unsigned int cipherTextLength, byte *plainText);
};

/// abstract base class for public-key signers and verifiers

/** This class provides an interface common to signers and verifiers
	for querying their signature lengths and creating message
	accumulators.
*/
class PK_SignatureSystem
{
public:
	///
	virtual ~PK_SignatureSystem() {};

	/// signature length support by this object (as either input or output)
	virtual unsigned int SignatureLength() const =0;

	/// create a new HashModule to accumulate the message to be signed or verified
	virtual HashModule * NewMessageAccumulator() const =0;
};

/// abstract base class for public-key signers

/** A signer is also a private signature key.  It contains both the
	key and the algorithm to perform the signature.
*/
class PK_Signer : public virtual PK_SignatureSystem
{
public:
	/// key too short exception, may be thrown by Sign() or SignMessage()
	class KeyTooShort : public Exception
	{
	public:
		KeyTooShort() : Exception("PK_Signer: key too short") {}
	};

	/// sign and delete messageAccumulator
	/** Preconditions:
			\begin{itemize}
			\item messageAccumulator was obtained by calling NewMessageAccumulator()
			\item HashModule::Final() has not been called on messageAccumulator
			\item size of signature == SignatureLength()
			\end{itemize}
	*/
	virtual void Sign(RandomNumberGenerator &rng, HashModule *messageAccumulator, byte *signature) const =0;

	/// sign a message
	/** Precondition: size of signature == SignatureLength() */
	virtual void SignMessage(RandomNumberGenerator &rng, const byte *message, unsigned int messageLen, byte *signature) const;
};

/// abstract base class for public-key verifiers

/** A verifier is also a public verification key.  It contains both the
	key and the algorithm to perform the verification.
*/
class PK_Verifier : public virtual PK_SignatureSystem
{
public:
	/// check whether sig is a valid signature for messageAccumulator, and delete messageAccumulator
	/** Preconditions:
			\begin{itemize}
			\item messageAccumulator was obtained by calling NewMessageAccumulator()
			\item HashModule::Final() has not been called on messageAccumulator
			\item length of signature == SignatureLength()
			\end{itemize}
	*/
	virtual bool Verify(HashModule *messageAccumulator, const byte *sig) const =0;

	/// check whether sig is a valid signature for message
	/** Precondition: size of signature == SignatureLength() */
	virtual bool VerifyMessage(const byte *message, unsigned int messageLen, const byte *sig) const;
};

/// abstract base class for public-key signers and verifiers with recovery

/** In a signature scheme with recovery, a verifier is able to extract
	a message from its valid signature.
*/
class PK_SignatureSystemWithRecovery : public virtual PK_SignatureSystem
{
public:
	/// length of longest message that can be fully recovered
	virtual unsigned int MaximumRecoverableLength() const =0;

	/// whether or not messages longer than MaximumRecoverableLength() can be signed
	/** If this function returns false, any message longer than
		MaximumRecoverableLength() will be truncated for signature
		and will fail verification.
	*/
	virtual bool AllowLeftoverMessage() const =0;
};

/// abstract base class for public-key signers with recovery

class PK_SignerWithRecovery : public virtual PK_SignatureSystemWithRecovery, public PK_Signer
{
};

/// abstract base class for public-key verifiers with recovery

/** A PK_VerifierWithRecovery can also be used the same way as a PK_Verifier,
	where the signature and the entire message is given to Verify() or
	VerifyMessage() as input.
*/
class PK_VerifierWithRecovery : public virtual PK_SignatureSystemWithRecovery, public PK_Verifier
{
public:
	/// create a new HashModule to accumulate leftover message
	virtual HashModule * NewLeftoverMessageAccumulator(const byte *signature) const =0;

	/// partially recover a message from its signature, return length of recoverd message, or 0 if signature is invalid
	/** Preconditions:
			\begin{itemize}
			\item leftoverMessageAccumulator was obtained by calling NewLeftoverMessageAccumulator(signature)
			\item HashModule::Final() has not been called on leftoverMessageAccumulator
			\item length of signature == SignatureLength()
			\item size of recoveredMessage == MaximumRecoverableLength()
			\end{itemize}
	*/
	virtual unsigned int PartialRecover(HashModule *leftoverMessageAccumulator, byte *recoveredMessage) const =0;

	/// recover a message from its signature, return length of message, or 0 if signature is invalid
	/** This function should be equivalent to PartialRecover(NewLeftoverMessageAccumulator(signature), recoveredMessage).
		Preconditions:
			\begin{itemize}
			\item length of signature == SignatureLength()
			\item size of recoveredMessage == MaximumRecoverableLength()
			\end{itemize}
	*/
	virtual unsigned int Recover(const byte *signature, byte *recoveredMessage) const =0;
};

/// abstract base class for domains of simple key agreement protocols

/** A key agreement domain is a set of parameters that must be shared
	by two parties in a key agreement protocol, along with the algorithms
	for generating key pairs and deriving agreed values.
*/
class PK_SimpleKeyAgreementDomain
{
public:
	virtual ~PK_SimpleKeyAgreementDomain() {}

	/// return whether the domain parameters stored in this object are valid
	virtual bool ValidateDomainParameters(RandomNumberGenerator &rng) const =0;
	/// return length of agreed value produced
	virtual unsigned int AgreedValueLength() const =0;
	/// return length of private keys in this domain
	virtual unsigned int PrivateKeyLength() const =0;
	/// return length of public keys in this domain
	virtual unsigned int PublicKeyLength() const =0;
	/// generate private/public key pair
	/** Preconditions:
			\begin{itemize}
			\item size of privateKey == PrivateKeyLength()
			\item size of publicKey == PublicKeyLength()
			\end{itemize}
	*/
	virtual void GenerateKeyPair(RandomNumberGenerator &rng, byte *privateKey, byte *publicKey) const =0;
	/// derive agreed value from your private key and couterparty's public key, return false in case of failure
	/** Note: If you have previously validated the public key, use validateOtherPublicKey=false to save time.
	/** Preconditions:
			\begin{itemize}
			\item size of agreedValue == AgreedValueLength()
			\item length of privateKey == PrivateKeyLength()
			\item length of otherPublicKey == PublicKeyLength()
			\end{itemize}
	*/
	virtual bool Agree(byte *agreedValue, const byte *privateKey, const byte *otherPublicKey, bool validateOtherPublicKey=true) const =0;
};

/// abstract base class for domains of authenticated key agreement protocols

/** In an authenticated key agreement protocol, each party has two
	key pairs. The long-lived key pair is called the static key pair,
	and the short-lived key pair is called the ephemeral key pair.
*/
class PK_AuthenticatedKeyAgreementDomain
{
public:
	virtual ~PK_AuthenticatedKeyAgreementDomain() {}

	/// return whether the domain parameters stored in this object are valid
	virtual bool ValidateDomainParameters(RandomNumberGenerator &rng) const =0;
	/// return length of agreed value produced
	virtual unsigned int AgreedValueLength() const =0;

	/// return length of static private keys in this domain
	virtual unsigned int StaticPrivateKeyLength() const =0;
	/// return length of static public keys in this domain
	virtual unsigned int StaticPublicKeyLength() const =0;
	/// generate static private/public key pair
	/** Preconditions:
			\begin{itemize}
			\item size of privateKey == StaticPrivateKeyLength()
			\item size of publicKey == StaticPublicKeyLength()
			\end{itemize}
	*/
	virtual void GenerateStaticKeyPair(RandomNumberGenerator &rng, byte *privateKey, byte *publicKey) const =0;

	/// return length of ephemeral private keys in this domain
	virtual unsigned int EphemeralPrivateKeyLength() const =0;
	/// return length of ephemeral public keys in this domain
	virtual unsigned int EphemeralPublicKeyLength() const =0;
	/// generate ephemeral private/public key pair
	/** Preconditions:
			\begin{itemize}
			\item size of privateKey == EphemeralPrivateKeyLength()
			\item size of publicKey == EphemeralPublicKeyLength()
			\end{itemize}
	*/
	virtual void GenerateEphemeralKeyPair(RandomNumberGenerator &rng, byte *privateKey, byte *publicKey) const =0;

	/// derive agreed value from your private keys and couterparty's public keys, return false in case of failure
	/** Note: The ephemeral public key will always be validated.
		If you have previously validated the static public key, use validateStaticOtherPublicKey=false to save time.
		Preconditions:
			\begin{itemize}
			\item size of agreedValue == AgreedValueLength()
			\item length of staticPrivateKey == StaticPrivateKeyLength()
			\item length of ephemeralPrivateKey == EphemeralPrivateKeyLength()
			\item length of staticOtherPublicKey == StaticPublicKeyLength()
			\item length of ephemeralOtherPublicKey == EphemeralPublicKeyLength()
			\end{itemize}
	*/
	virtual bool Agree(byte *agreedValue,
		const byte *staticPrivateKey, const byte *ephemeralPrivateKey,
		const byte *staticOtherPublicKey, const byte *ephemeralOtherPublicKey,
		bool validateStaticOtherPublicKey=true) const =0;
};

/// abstract base class for all objects that support precomputation

/** The class defines a common interface for doing precomputation,
	and loading and saving precomputation.
*/
class PK_Precomputation
{
public:
	///
	virtual ~PK_Precomputation() {}

	///
	/** The exact semantics of Precompute() is varies, but
		typically it means calculate a table of n objects
		that can be used later to speed up computation.
	*/
	virtual void Precompute(unsigned int n) =0;

	/// retrieve previously saved precomputation
	virtual void LoadPrecomputation(BufferedTransformation &storedPrecomputation) =0;
	/// save precomputation for later use
	virtual void SavePrecomputation(BufferedTransformation &storedPrecomputation) const =0;
};

///
template <class T> class PK_WithPrecomputation : public virtual T, public virtual PK_Precomputation
{
};

NAMESPACE_END

#endif
