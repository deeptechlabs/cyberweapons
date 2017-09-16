/* Compile options:

   -DTEST_VERSION compiles the test version, which encrypts sample data/keys.
   -DTIME_TRIAL compiles a version which encrypts 10MB of data in CFB mode
				for timing tests.
   -DSETUP_TRIAL compiles a version which performs the password/S-box setup
				 repeatedly for brute-force crack timing tests.
   -DUSE_CBC compiles a simple encryption program using CBC mode.
   (no define) compiles a simple encryption program using CFB mode.

   -DSHOW_SBOXES displays the S-Boxes for each key.

   -DASM_ENCRYPT includes extra code for the 80x86 16-bit fast encrypt()
				 routine.
   -DASM_ENCRYPT32 includes extra code for the 80x86 32-bit even faster
				   encrypt() routine.
	Note that these asm routines are meant to be used in CFB mode, and
	neither have the code for CBC handling, however this is very simple to
	add */

/* Define the following if using the asm encrypt() routine */

#if defined( ASM_ENCRYPT ) || defined( ASM_ENCRYPT_32 )
  #include <dos.h>		/* Needed for pointer normalisation */
#endif /* ASM_ENCRYPT || ASM_ENCRYPT_32 */

#ifdef ASM_ENCRYPT_32
  #define encrypt	encrypt32		/* Use 32-bit encrypt() code */
#endif /* ASM_ENCRYPT_32 */

/* The following are system-dependant: Unsigned 8, 16, 32-bit quantities.*/

typedef unsigned char       BYTE;
typedef unsigned short      WORD;
typedef unsigned long       LONG;

typedef unsigned char		BOOLEAN;

/* Useful defines */

#define ERROR	-1
#define OK		0

#define TRUE	1
#define FALSE	0

/* The block size (in bytes).  Use 8 bytes for a DES-a-like (64 bits),
   16 or 32 bytes for better security (128 or 256 bits) */

#define BLOCKSIZE	16

/* The S-Boxes used for encryption */

#define SBOX_SIZE		( 256 * sizeof( LONG ) )	/* 256 LONG's per S-Box */

#define SBOX_SHIFT	2	/* The amount to shift a byte index by to get the
						   basic machine word size of 32 bits */

extern BYTE *tempKey;			/* The temporary key used to set up the S-Boxes */
#if defined( ASM_ENCRYPT ) || defined( ASM_ENCRYPT_32 )
  extern WORD sBoxBase;			/* S-Box segment address */
  extern LONG *sBoxAddress;		/* Non-adjusted S-Box address */
#else
  extern LONG *sBoxes1, *sBoxes2;	/* The S-Boxes themselves */
#endif /* ASM_ENCRYPT || ASM_ENCRYPT_32 */

/* The default salt value used to initialize the LCRNG in initSBoxes().
   Changing this for each file precludes the use of precomputed encrypted
   data for very fast checking against known plaintext */

#define DEFAULT_SALT	0L

/* Prototypes for functions in NSEA.C */

void initNSEA( void );
void endNSEA( void );
void initIV( const LONG salt );
void initSBoxes( BYTE *key, int keyLength, const LONG salt );
void encrypt( BYTE *src, BYTE *dest );
void decrypt( BYTE *src, BYTE *dest );
void encryptCFB( BYTE *buffer, int length );
void decryptCFB( BYTE *buffer, int length );
#ifdef ASM_ENCRYPT_32
  void encrypt32( BYTE *src, BYTE *dest );
#endif /* ASM_ENCRYPT_32 */
LONG getRandomLong( void );