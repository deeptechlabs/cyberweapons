/****************************************************************************
*																			*
*						PGP Compatibility Code Header File					*
*						Copyright Peter Gutmann 1996-1997					*
*																			*
****************************************************************************/

#ifndef _PGP_DEFINED

#define _PGP_DEFINED

#ifndef _STREAM_DEFINED
  #if defined( INC_ALL )
	#include "stream.h"
  #elif defined INC_CHILD
	#include "../keymgmt/stream.h"
  #else
	#include "keymgmt/stream.h"
  #endif /* Compiler-specific includes */
#endif /* _STREAM_DEFINED */

/* Magic numbers for message packets.  These values don't include the length
   indicator bytes, typical length values are shown in the comments */

#define PGP_CTB_PKE			0x84	/* (85) PKC-encrypted session key */
#define PGP_CTB_SIGNATURE	0x88	/* (89) Signature */
#define PGP_CTB_SECKEY		0x94	/* (95) Secret key packet */
#define PGP_CTB_PUBKEY		0x98	/* (99) Public key packet */
#define PGP_CTB_COPR		0xA0	/* (A3) Compressed data */
#define PGP_CTB_ENCR		0xA4	/* (A6) Encrypted data */
#define PGP_CTB_DATA		0xAC	/* (AE) Raw data */
#define PGP_CTB_TRUST		0xB0	/* (B0) Trust packet */
#define PGP_CTB_USERID		0xB4	/* (B4) Userid packet */

/* A macro to extract the type bits from the full CTB, which includes
   length-of-length bits in the two LSB's */

#define getCTB( ctb )		( ( ctb ) & ~3 )

/* Version information */

#define PGP_VERSION_2		2		/* Version number byte for PGP 2.0 */
#define PGP_VERSION_3		3		/* Version number byte for PGP 3.0 or
									   legal-kludged 2.0 */
/* Public-key algorithms */

#define PGP_ALGO_RSA		1		/* RSA PKC algorithm */
#define PGP_ALGO_ELGAMAL	16		/* ElGamal PKC algorithm */
#define PGP_ALGO_DSA		17		/* DSA signature algorithm */

/* Conventional encryption algorithms */

#define PGP_ALGO_NONE		0		/* No CKE algorithm */
#define PGP_ALGO_IDEA		1		/* IDEA cipher */
#define PGP_ALGO_3DES		2		/* Triple DES */
#define PGP_ALGO_CAST5		3		/* CAST-128 */

/* Hash algorithms */

#define PGP_ALGO_MD5		1		/* MD5 message digest */

/* Compression algorithms */

#define PGP_ALGO_ZIP		1		/* ZIP compression */

/* Signed data types */

#define PGP_SIG_BINDATA		0x00	/* Binary data */
#define PGP_SIG_TEXT		0x01	/* Canonicalised text data */
#define	PGP_SIG_CERT0		0x10	/* Key certificate, unknown assurance */
#define	PGP_SIG_CERT1		0x11	/* Key certificate, no assurance */
#define	PGP_SIG_CERT2		0x12	/* Key certificate, casual assurance */
#define	PGP_SIG_CERT3		0x13	/* Key certificate, strong assurance */
#define PGP_SIG_KRL			0x20	/* Key revocation */
#define PGP_SIG_CRL			0x30	/* Certificate revocation */
#define	PGP_SIG_TS			0x40	/* Timestamp signature */

/* The maximum size of an MPI (4096 bits) */

#define PGP_MAX_MPISIZE		512

/* The maximum size of a PGP user ID.  Note that this is larger than the
   cryptlib-wide maximum user ID size */

#define PGP_MAX_USERIDSIZE	256

/* The size of the PGP key ID (the 64 LSB's of the RSA key) */

#define PGP_KEYID_SIZE		8

/* The size of the IDEA IV and key */

#define PGP_IDEA_IVSIZE		8
#define PGP_IDEA_KEYSIZE	16

/* The size of a BYTE, WORD, and LONG in the PGP packet format */

#define PGP_SIZE_BYTE		1
#define PGP_SIZE_WORD		2
#define PGP_SIZE_LONG		4

/* Prototypes for functions in pgp_misc.c */

int pgpPasswordToKey( CRYPT_CONTEXT cryptContext, const char *password,
					  const int passwordLength );
long pgpGetLength( STREAM *stream, const int ctb );
int pgpReadMPI( STREAM *stream, BYTE *mpReg );
WORD pgpChecksumMPI( BYTE *data, int length );

#endif /* _PGP_DEFINED */
