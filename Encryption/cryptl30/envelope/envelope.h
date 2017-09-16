/****************************************************************************
*																			*
*						 Enveloping Routines Header File					*
*						Copyright Peter Gutmann 1996-1999					*
*																			*
****************************************************************************/

#ifndef _ENV_DEFINED

#define _ENV_DEFINED

#ifndef _STREAM_DEFINED
  #if defined( INC_ALL )
	#include "stream.h"
  #elif defined INC_CHILD
	#include "../keymgmt/stream.h"
  #else
	#include "keymgmt/stream.h"
  #endif /* Compiler-specific includes */
#endif /* _STREAM_DEFINED */
#ifndef NO_COMPRESSION
  #if defined( INC_ALL )
	#include "zlib.h"
  #elif defined( INC_CHILD )
	#include "../zlib/zlib.h"
  #else
	#include "zlib/zlib.h"
  #endif /* Compiler-specific includes */
#endif /* NO_COMPRESSION */

/* Types of actions which can be performed on a piece of data.  The two key
   exchange actions are handled identically, but are given different tags
   because we place PKC-based key exchange actions (which may be handled
   automatically) before conventional key exchange actions (which usually
   require manual intervention for passphrases).  For this reason the actions
   are given in their sort order (ie ACTION_KEYEXCHANGE_PKC precedes
   ACTION_KEYEXCHANGE in the action list) */

typedef enum {
	ACTION_NONE,					/* Non-action */

	/* Pre-actions */
	ACTION_KEYEXCHANGE_PKC,			/* Generate/read PKC exchange information */
	ACTION_KEYEXCHANGE,				/* Generate/read key exchange information */

	/* Actions */
	ACTION_COMPRESS,				/* Compress */
	ACTION_HASH,					/* Hash */
	ACTION_CRYPT,					/* En/decrypt */

	/* Post-actions */
	ACTION_SIGN						/* Generate/check signature */
	} ACTION_TYPE;

/* An 'action list' which defines what we need to do to the content when
   enveloping data.  There are three action lists, one for actions to perform
   before enveloping data, one to perform during enveloping, and one to
   perform after enveloping.  ACTION_KEYEXCHANGE and ACTION_KEYEXCHANGE_PKC
   are found in the pre-enveloping list, ACTION_SIGN in the post-enveloping 
   list, and everything else in the during-enveloping list.  A collection of 
   similar actions is called an action group.

   Some actions are many-to-one, in which a number of controlling actions in
   one list may act on a single subject action in another list (for example a
   number of signature actions may sign the output from a single hash
   action).  This is handled by having the controlling actions maintain
   pointers to the subject action, for example a number of key export actions
   would point to one session encryption action (the export action exports
   the session key).

   The ordering of actions in the lists is:

	Pre: ACTION_KEYEXCHANGE_PKC, ACTION_KEYEXCHANGE
	Action: ACTION_COMPRESS, ACTION_HASH, or ACTION_CRYPT
	Post: ACTION_SIGN

   There may also be shift actions in the main action list */

typedef struct AI {
	/* Type of list item and link information */
	ACTION_TYPE action;				/* Type of action to perform */
	struct AI *next;				/* Next item in the list */

	/* Variables to handle controlling/subject actions.  The associated
	   action points to the subject action associated with a controlling
	   action if this is a controlling action.  The needsController flag
	   records whether this is a subject action which still requires a
	   controlling action.  This allows us to identify unused subject actions
	   more easily than by scanning all controller->subject relationships.
	   The addedAutomatically flag records whether the action was added
	   automatically and invisibly to the caller as a result of adding a
	   different action.  This is to ensure we don't return an error the
	   first time the caller adds an action which is identical to an
	   automatically added action */
	struct AI *associatedAction;	/* Associated action */
	BOOLEAN needsController;		/* Whether it needs a controlling action */
	BOOLEAN addedAutomatically;		/* Whether action added automatically */

	/* Information related to the action.  These fields contain various
	   pieces of information required as part of the action.  The crypt
	   handle usually contains the internal encryption context needed to
	   perform the action (eg encryption, hashing, signing), but may also
	   contain a certificate when we envelope data in CMS format.  If we're
	   generating CMS signatures, there may be extra attribute data present 
	   which is included in the signature.  Finally, there may also be
	   auxiliary information present which is required for special processing
	   (examples being URL's for timestamp servers) */
	CRYPT_CONTEXT iCryptHandle;		/* Encryption handle for action */
	CRYPT_CERTIFICATE iExtraData;	/* Extra attribute data for CMS sigs.*/
	void *auxInfo;					/* Misc.extra information */
	int encodedSize;				/* The encoded size of the action */
	} ACTION_LIST;

/* Looking up an action in an action list has one of the following outcomes.
   The two 'action present' results are for the case where the action is
   already present and shouldn't be added again, and where the action is
   present from being added as an (invisible to the user) side-effect of
   another action being added, so that this attempt to add it should be
   reported as CRYPT_OK rather than CRYPT_INITED */

typedef enum {
	ACTION_RESULT_OK,				/* Action not present, can be added */
	ACTION_RESULT_EMPTY,			/* Action list is empty */
	ACTION_RESULT_INITED,			/* Action present (CRYPT_INITED) */
	ACTION_RESULT_PRESENT			/* Action present (CRYPT_OK) */
	} ACTION_RESULT;

/* A 'content list' which is used to store objects found in the non-data
   portion of the envelope until we can do something with them when de-
   enveloping data.  If the envelope contains encrypted data this list
   contains the key exchange information until we get a key exchange key to
   recover the session key.  If the envelope contains signed data this list
   contains the signature(s) until we get signature keys to check them.  The
   same list is used for two purposes at different times */

typedef struct CL {
	/* Link information */
	struct CL *next;				/* Next item in the list */

	/* The object contained in this list element */
	void *object;					/* The object data */
	int objectSize;					/* Size of the object */

	/* Details on the object.  Here we store whatever is required to process
	   the object without having to call queryObject() for the details */
	CRYPT_ATTRIBUTE_TYPE envInfo;	/* Env.info required to continue */
	CRYPT_FORMAT_TYPE formatType;	/* Data format (clib vs CMS) */
	BYTE keyID[ CRYPT_MAX_HASHSIZE ];/* cryptlib key ID */
	int keyIDsize;
	void *issuerAndSerialNumber;	/* CMS key ID */
	int issuerAndSerialNumberSize;
	CRYPT_ALGO cryptAlgo;			/* Encryption algo.for this object */
	CRYPT_MODE cryptMode;			/* Encrytion mode for this object */
	BYTE saltIV[ CRYPT_MAX_HASHSIZE ];/* Salt for password-derived key, */
	int saltIVsize;					/*   IV for session encr.context */
	int keySetupIterations;			/* Iterations for pw-derived key */
	CRYPT_ALGO hashAlgo;			/* Hash algo.for signed data */

	/* Additional information obtained when processing the content */
	CRYPT_HANDLE iSigCheckKey;		/* Signature check key */
	CRYPT_CERTIFICATE iExtraData;	/* Extra data in CMS signatures */

	/* We only need to process an object once, once we've done this we store
	   the processing result so that any further attempts to process the
	   object will return the previously obtained result (an object can be
	   processed multiple times if the user wanders up and down the content
	   list using the cursor management capabilities) */
	BOOLEAN processed;				/* Whether object has been processed */
	int processingResult;			/* Result of processing */
	} CONTENT_LIST;

/* The current state of the (de)enveloping.  The states are the predata state
   (when we're performing final setup steps and handling header information
   in the envelope), the data state (when we're enveloping data), the
   postdata state (when we're handling trailer information), and the
   extradata state (when we're processing out-of-band data such as the data
   associated with detached signatures) */

typedef enum {
	STATE_PREDATA,					/* Emitting header information */
	STATE_DATA,						/* During (de)enveloping of data */
	STATE_POSTDATA,					/* After (de)enveloping of data */
	STATE_EXTRADATA,				/* Additional out-of-band data */
	STATE_FINISHED					/* Finished processing */
	} ENVELOPE_STATE;

/* The current state of the processing of headers which contain non-data
   during the enveloping process.  Before the enveloping of data begins, the
   user pushes in a variety of enveloping information (which in turn might
   trigger the creation of more internal information objects).  Once the
   enveloping begins, this enveloping information is encoded as ASN.1
   structures and written into the envelope buffer.  This encoding process
   can be interrupted at any point when the envelope buffer fills up, so we
   break it down into a series of atomic states between which the enveloping
   process can be interrupted by the caller removing data from the envelope.

   There are two sets of states, the first set which covers the encoding of
   the header information at the start of the envelope (only key exchange
   information requires this), and the second which covers the information at
   the end of the envelope (only signatures require this) */

typedef enum {
	ENVSTATE_NONE,					/* No header processing/before header */

	/* Header state information */
	ENVSTATE_HEADER,				/* Emitting header */
	ENVSTATE_KEYINFO,				/* Emitting key exchange information */
	ENVSTATE_ENCRINFO,				/* Emitting EncrContentInfo information */

	/* Trailer state information */
	ENVSTATE_SIGNATURE,				/* Emitting signatures */
	ENVSTATE_EOC,					/* Emitting EOC octets */

	ENVSTATE_DONE					/* Finished processing header/trailer */
	} ENV_STATE;

/* The current state of the processing of headers which contain non-data
   in the envelope during the de-enveloping process.  This is implemented as
   a somewhat complex FSM because the enveloping routines give the user the
   ability to push in arbitrary amounts of data corresponding to ASN.1
   structures and simultaneously pop out data/information based on decoding
   them.  A typical complex enveloped type might contain a number of headers,
   a session key encrypted with 18 different public keys, five varieties of
   signature type, and God knows what else, of which the caller might feed us
   500 bytes - a small fraction of the total data - and then ask for
   information on what they've just fed us.  We have to remember how far we
   got (halfway through an RSA-encrypted DES key fifteen levels of nesting
   down in an ASN.1 structure), process everything we can, and then get back
   to them on what we found.  Then they feed us another few hundred bytes and
   the whole thing starts anew.

   The state machine works by processing one complete object or part of an
   object at a time and then moving on to the next state which corresponds to
   handling another part of the object or another object.  If there isn't
   enough data present to process a part or subpart, we return an underflow
   error and try again when more data is added */

typedef enum {
	DEENVSTATE_NONE,				/* No header processing/before header */

	/* Header state information */
	DEENVSTATE_SET_ENCR,			/* Processing start of SET OF EncrKeyInfo */
	DEENVSTATE_ENCR,				/* Processing EncrKeyInfo records */
	DEENVSTATE_ENCRCONTENT,			/* Processing EncrContentInfo */

	DEENVSTATE_SET_HASH,			/* Processing start of SET OF DigestAlgoID */
	DEENVSTATE_HASH,				/* Processing DigestAlgoID records */
	DEENVSTATE_CONTENT,				/* Processing ContentInfo */

	DEENVSTATE_DATA,				/* Processing data payload */

	/* Trailer state information */
	DEENVSTATE_CERTSET,				/* Processing optional cert chain */
	DEENVSTATE_SET_SIG,				/* Processing start of SET OF Signature */
	DEENVSTATE_SIG,					/* Processing Signature records */
	DEENVSTATE_EOC,					/* Processing end-of-contents octets */

	DEENVSTATE_DONE					/* Finished processing header/trailer */
	} DEENV_STATE;

/* The current state of processing of headers for PGP messages.  These are
   somewhat different to the ASN.1-encoded objects used by cryptlib in that
   many of the objects are emitted as discrete packets rather than the nested
   objects used in ASN.1 objects.  This makes some parts of the processing
   much easier (less length information to track) and some parts harder
   (since just about anything could appear next, you need to maintain a
   lookahead to figure out what to do next, but you may run out of data
   before you can determine which state is next) */

typedef enum {
	PGP_ENVSTATE_NONE,				/* No message processing/before message */

	PGP_ENVSTATE_DONE				/* Finished processing message */
	} PGP_ENV_STATE;

typedef enum {
	PGP_DEENVSTATE_NONE,			/* No message processing/before message */

	PGP_DEENVSTATE_PKC,				/* PKC-encrypted session key */
	PGP_DEENVSTATE_ENCR,			/* Encrypted data packet */
	PGP_DEENVSTATE_COPR,			/* Compressed data */
	PGP_DEENVSTATE_SIGNED,			/* Signature packet */
	PGP_DEENVSTATE_PLAINTEXT,		/* Plaintext data */

	PGP_DEENVSTATE_DONE				/* Finished processing message */
	} PGP_DEENV_STATE;

/* The current state of processing of headers for data segments nested inside
   the OCTET STRING which contains the envelopes content.  Since we can run
   out of data at any point, we have to preserve the current state so we can
   continue when we get more data */

typedef enum {
	SEGHDRSTATE_NONE,				/* No header processing/before header */
	SEGHDRSTATE_LEN_OF_LEN,			/* Expecting OCTET STRING len-of-len */
	SEGHDRSTATE_LEN,				/* Processing OCTET STRING length */
	SEGHDRSTATE_END,				/* Expecting second end-of-contents oct.*/
	SEGHDRSTATE_DONE				/* Parsed entire header */
	} SEGHDR_STATE;

/* The structure which stores the information on an envelope */

typedef struct EI {
	/* The envelope type (underlying data format), usage (signing,
	   encryption, compression, etc), and modifiers (data + signature ->
	   detached signature) */
	CRYPT_FORMAT_TYPE type;
	ACTION_TYPE usage;
	BOOLEAN detachedSig;

	/* The inner content type, defaulting to plain data if not explicitly set
	   by the user */
	CRYPT_CONTENT_TYPE contentType;

	/* The list of actions to perform on the data.  There are three sets of
	   actions, the preActions (output of encrypted session keys and
	   whatnot), the main actions (encryption and hashing), and the
	   postActions (output of signatures) */
	ACTION_LIST *preActionList;
	ACTION_LIST *actionList;
	ACTION_LIST *postActionList;

	/* Several action groups produce information which is prepended or
	   appended to the data.  The following variables record the encoded size
	   of this information.  In some cases the size of the appended
	   information isn't known when the enveloping is started so we have to
	   use an indefinite-length encoding for the outermost wrapper, if this
	   is the case then we set the indefinite trailer flag to indicate that
	   a definite-length encoding shouldn't be used even if the payload size
	   is known */
	int cryptActionSize;			/* Size of key exchange actions */
	int signActionSize;				/* Size of signatures */
	int extraDataSize;				/* Size of any extra data */
	BOOLEAN hasIndefiniteTrailer;	/* Whether trailer size is indefinite */

	/* When prepending or appending header or trailer information to an
	   envelope we need to record the current position in the action list so
	   we can continue later if we run out of room */
	ACTION_LIST *lastAction;

	/* When de-enveloping we may have objects present which can't be used
	   until user-supplied de-enveloping information is added to the
	   envelope.  We store these in a linked list in memory until the
	   information needed to work with them is present.  We also store a
	   pointer to the current position in the list which is used when
	   traversing the list */
	CONTENT_LIST *contentList, *contentListCurrent;

	/* The public-key encryption/private-key decryption and signature-check
	   keysets which are used to look up any keys which are required during
	   the enveloping/de-enveloping process */
	CRYPT_KEYSET iDecryptionKeyset;
	CRYPT_KEYSET iEncryptionKeyset;
	CRYPT_KEYSET iSigCheckKeyset;

	/* When we're encrypting or decrypting the envelope payload, the one
	   action we'll be performing constantly is encryption.  The following
	   holds the internal bulk data encryption context which saves pulling it
	   out of the action list when it's needed.  Note that since there is a
	   second reference held in the action list, there's no need to
	   explicitly delete this when we destroy the envelope object since it's
	   already been destroyed when the action list is destroyed */
	CRYPT_CONTEXT iCryptContext;

	/* Similarly, when we're hashing data it's convenient to have direct
	   access to the hash actions to save having to walk down the action
	   list, so we store a direct pointer to the start of the hash actions
	   here.  This pointer is only valid while the hashing is taking place,
	   once there is no more data to be hashed it is reset to NULL and access
	   to hash actions for signature-checking purposes is done via the usual
	   action list access routines */
	ACTION_LIST *hashActions;

	/* When we check a CMS signature, there may be a cert collection attached
	   to the SignedData.  This is imported into the following certificate
	   object */
	CRYPT_CERTIFICATE iSignerChain;

	/* With some types of key management, we may have originator certs 
	   present.  These are held in the following certificate object */
	CRYPT_CERTIFICATE iOriginatorChain;

	/* The encryption/hashing/signature defaults for this envelope.  These
	   are recorded here for two reasons.  Firstly, we need to freeze the
	   defaults when the envelope is created so that a later change of the
	   default value won't affect the enveloping process.  Secondly,
	   different envelope types have different defaults, and setting them
	   once at envelope creation is easier than checking the envelope type
	   and choosing the appropriate algorithm every time we need to use a
	   default parameter */
	CRYPT_ALGO defaultHash;			/* Default hash algorithm */
	CRYPT_ALGO defaultAlgo;			/* Default encryption algorithm */

#ifndef NO_COMPRESSION
	/* zlib stream compression data structure used to hold the compression/
	   decompression state */
	z_stream zStream;				/* zlib state variable */
	BOOLEAN zStreamInited;			/* Whether compression is inited */
#endif /* NO_COMPRESSION */

	/* Buffer information */
	BYTE *buffer;					/* Data buffer */
	int bufSize;					/* Total buffer size */
	int bufPos;						/* Last data position in buffer */

	/* Auxiliary buffer used as a staging area for holding objects such as
	   key exchange information and signatures which may not currently fit
	   into the main buffer.  These are generated into the auxiliary buffer
	   and then copied into the main buffer as required */
	BYTE *auxBuffer;				/* Buffer for various objects */
	int auxBufSize;					/* Total aux.buffer size */
	int auxBufPos;					/* Current position in auxiliary buffer */
	STREAM auxStream;				/* Auxiliary buffer I/O stream */

	/* When the caller knows how large the payload will be, they can advise
	   the enveloping code of this, which allows a more efficient encoding of
	   the data.  The following variable records the payload size */
	long payloadSize;

	/* The current state of header processing.  The cryptlib/CMS and PGP
	   processing states are kept seperate (although they could be merged
	   into the same variable) because they are conceptually seperate and
	   shouldn't really be treated as the same thing */
	ENVELOPE_STATE state;			/* Current state of processing */
	ENV_STATE envState;				/* Current state of env.non-data proc.*/
	DEENV_STATE deenvState;			/* Current state of deenv.non-data proc.*/
#ifndef NO_PGP
	PGP_ENV_STATE pgpEnvState;		/* Current state of PGP env.n-d proc. */
	PGP_DEENV_STATE pgpDeenvState;	/* Current state of PGP deenv.n-d proc.*/
#endif /* NO_PGP */
	int hdrSetLength;				/* Remaining bytes in SET OF EKeyInfo */
	BOOLEAN isDeenvelope;			/* Whether we're de-enveloping data */

	/* The overall envelope status.  Some error states (underflow/overflow
	   enveloping information errors, randomness errors, and a few others)
	   are recoverable whereas other states (bad data) aren't recoverable.
	   If we run into a nonrecoverable error, we remember the status here so
	   that any further attempts to work with the envelope will return this
	   status */
	int errorState;

	/* Information on the current OCTET STRING segment in the buffer during
	   the enveloping process.  We keep track of the segment start point (the
	   byte after the OCTET STRING tag), the segment data start point (which
	   may move when the segment is terminated if the length encoding shrinks
	   due to a short segment), the remaining data in the current segment
	   (explicitly declared as a longint since we may be processing data
	   which came from a 32-bit machine on a 16-bit machine), and whether
	   we've just completed a segment (which we need to do before we can pop
	   any data from the envelope).  In addition we track where the last
	   completed segment ends, as the buffer may contain one or more completed
	   segments followed by an incomplete segment, and any attempt to read
	   into the incomplete segment will require it to be completed first */
	int segmentStart;				/* Segment len+data start point */
	int segmentDataStart;			/* Segment data start point */
	long segmentSize;				/* Remaining data in segment */
	BOOLEAN segmentComplete;		/* Whether we've just completed a seg.*/
	int segmentDataEnd;				/* End of completed data */

	/* If the amount of data pushed in results in only part of a segment
	   header being available during the decoding process, we need to record
	   the state information so we can continue parsing the header when more
	   data is pushed.  The following variables record the state information
	   so that processing can be interrupted and resumed at any point */
	SEGHDR_STATE segHdrState;		/* State of segment header processing */
	long segHdrSegLength;			/* Current len.of seg.being processed */
	int segHdrCount;				/* Current length-of-length for seg.*/

	/* Once the low-level segment-processing code sees the end-of-contents
	   octets for the payload, we need to notify the higher-level code that
	   anything which follows is out-of-band data which needs to be processed
	   at a higher level.  The following flag records the fact that we've
	   seen the payload EOC and have moved to trailing out-of-band data.

	   Since the data after the EOC isn't directly retrievable by the user,
	   we use the dataLeft variable to keep track of how much of what's left
	   in the envelope is payload which can be copied out */
	BOOLEAN endOfContents;
	int dataLeft;

	/* If we're encrypting data using a block cipher mode we need to add
	   PKCS #5 padding to the last segment to make it a multiple of the block
	   size */
	BOOLEAN needsPadding;			/* Whether to add PKCS #5 padding */

	/* Block cipher buffer for leftover bytes.  This contains any bytes
	   remaining to be en/decrypted when the input data size isn't a
	   multiple of the cipher block size */
	BYTE blockBuffer[ CRYPT_MAX_IVSIZE ];	/* Buffer of bytes */
	int blockBufferPos;				/* Position in buffer */
	int blockSize;					/* Cipher block size */
	int blockSizeMask;				/* Mask for blockSize-sized blocks */

	/* Error information */
	CRYPT_ATTRIBUTE_TYPE errorLocus;/* Error locus */
	CRYPT_ERRTYPE_TYPE errorType;	/* Error type */

	/* Pointers to the enveloping/deenveloping functions */
	int ( *addInfo )( struct EI *envelopeInfoPtr,
					  const CRYPT_ATTRIBUTE_TYPE envInfo,
					  const void *value, const int valueLength );
	int ( *emitPreamble )( struct EI *envelopeInfoPtr );
	int ( *emitPostamble )( struct EI *envelopeInfoPtr );
	int ( *processPreamble )( struct EI *envelopeInfoPtr );
	int ( *processPostamble )( struct EI *envelopeInfoPtr );
	int ( *processExtraData )( struct EI *envelopeInfoPtr, const void *buffer,
							   const int length );
	int ( *copyToEnvelope )( struct EI *envelopeInfoPtr, const BYTE *buffer,
							 const int length );
	int ( *copyFromEnvelope )( struct EI *envelopeInfoPtr, BYTE *buffer,
							   int length );
	int ( *copyToDeenvelope )( struct EI *envelopeInfoPtr,
							   const BYTE *buffer, int length );
	int ( *copyFromDeenvelope )( struct EI *envelopeInfoPtr, BYTE *buffer,
								 int length );

	/* When we clone an object, there are certain per-instance fields which
	   don't get cloned.  These fields are located after the following
	   member, and must be initialised by the cloning function */
	int _sharedEnd;					/* Dummy used for end of shared fields */

	/* The object's handle, used when sending messages to the object when 
	   only the xxx_INFO is available */
	CRYPT_HANDLE objectHandle;

	/* In multithreaded environments we need to protect the information from
	   access by other threads while we use it.  The following macro declares
	   the actual variables required to handle the object locking (the actual 
	   values are defined in cryptos.h) */
	DECLARE_OBJECT_LOCKING_VARS
	} ENVELOPE_INFO;

/* Determine the size of the envelope payload after PKCS #5 block padding.
   This isn't just the size rounded up to the nearest multiple of the block
   size since if the size is already a multiple of the block size, it
   expands by another block, so we make the payload look one byte longer
   before rounding to the block size to ensure the one-block expansion */

#define paddedSize( size, blockSize )	roundUp( payloadSize + 1, blockSize )

/* Prototypes for enveloping information/action management functions */

ACTION_LIST *createAction( const ACTION_TYPE actionType,
						   const CRYPT_HANDLE cryptHandle );
ACTION_LIST *findAction( ACTION_LIST *actionListPtr,
						 const ACTION_TYPE actionType );
ACTION_RESULT findCheckLastAction( ACTION_LIST **actionListStart,
								   ACTION_LIST **actionListPtrPtr,
								   const ACTION_TYPE actionType,
								   const CRYPT_CONTEXT cryptHandle );
int addAction( ACTION_LIST **actionListHeadPtrPtr,
			   ACTION_LIST **actionListPtr,
			   const ACTION_TYPE actionType,
			   const CRYPT_CONTEXT cryptContext );

/* Prepare the envelope for data en/decryption */

int initEnvelopeEncryption( ENVELOPE_INFO *envelopeInfoPtr,
							const CRYPT_CONTEXT cryptContext,
							const CRYPT_ALGO algorithm, const CRYPT_MODE mode,
							const BYTE *iv, const int ivLength,
							const BOOLEAN copyContext );

#endif /* _ENV_DEFINED */
