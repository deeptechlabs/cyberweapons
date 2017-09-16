/****************************************************************************
*																			*
*						  MD2 Message Digest Algorithm 						*
*						Copyright Peter Gutmann 1992-1996					*
*																			*
****************************************************************************/

#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "md2.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "md2.h"
#else
  #include "crypt.h"
  #include "hash/md2.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*							The MD2 Transformation							*
*																			*
****************************************************************************/

/* The MD2 S-box, which is derived (somehow) from the digits of pi */

static BYTE pi[ 256 ] = {
	0x29, 0x2E, 0x43, 0xC9, 0xA2, 0xD8, 0x7C, 0x01,
	0x3D, 0x36, 0x54, 0xA1, 0xEC, 0xF0, 0x06, 0x13,
	0x62, 0xA7, 0x05, 0xF3, 0xC0, 0xC7, 0x73, 0x8C,
	0x98, 0x93, 0x2B, 0xD9, 0xBC, 0x4C, 0x82, 0xCA,
	0x1E, 0x9B, 0x57, 0x3C, 0xFD, 0xD4, 0xE0, 0x16,
	0x67, 0x42, 0x6F, 0x18, 0x8A, 0x17, 0xE5, 0x12,
	0xBE, 0x4E, 0xC4, 0xD6, 0xDA, 0x9E, 0xDE, 0x49,
	0xA0, 0xFB, 0xF5, 0x8E, 0xBB, 0x2F, 0xEE, 0x7A,
	0xA9, 0x68, 0x79, 0x91, 0x15, 0xB2, 0x07, 0x3F,
	0x94, 0xC2, 0x10, 0x89, 0x0B, 0x22, 0x5F, 0x21,
	0x80, 0x7F, 0x5D, 0x9A, 0x5A, 0x90, 0x32, 0x27,
	0x35, 0x3E, 0xCC, 0xE7, 0xBF, 0xF7, 0x97, 0x03,
	0xFF, 0x19, 0x30, 0xB3, 0x48, 0xA5, 0xB5, 0xD1,
	0xD7, 0x5E, 0x92, 0x2A, 0xAC, 0x56, 0xAA, 0xC6,
	0x4F, 0xB8, 0x38, 0xD2, 0x96, 0xA4, 0x7D, 0xB6,
	0x76, 0xFC, 0x6B, 0xE2, 0x9C, 0x74, 0x04, 0xF1,
	0x45, 0x9D, 0x70, 0x59, 0x64, 0x71, 0x87, 0x20,
	0x86, 0x5B, 0xCF, 0x65, 0xE6, 0x2D, 0xA8, 0x02,
	0x1B, 0x60, 0x25, 0xAD, 0xAE, 0xB0, 0xB9, 0xF6,
	0x1C, 0x46, 0x61, 0x69, 0x34, 0x40, 0x7E, 0x0F,
	0x55, 0x47, 0xA3, 0x23, 0xDD, 0x51, 0xAF, 0x3A,
	0xC3, 0x5C, 0xF9, 0xCE, 0xBA, 0xC5, 0xEA, 0x26,
	0x2C, 0x53, 0x0D, 0x6E, 0x85, 0x28, 0x84, 0x09,
	0xD3, 0xDF, 0xCD, 0xF4, 0x41, 0x81, 0x4D, 0x52,
	0x6A, 0xDC, 0x37, 0xC8, 0x6C, 0xC1, 0xAB, 0xFA,
	0x24, 0xE1, 0x7B, 0x08, 0x0C, 0xBD, 0xB1, 0x4A,
	0x78, 0x88, 0x95, 0x8B, 0xE3, 0x63, 0xE8, 0x6D,
	0xE9, 0xCB, 0xD5, 0xFE, 0x3B, 0x00, 0x1D, 0x39,
	0xF2, 0xEF, 0xB7, 0x0E, 0x66, 0x58, 0xD0, 0xE4,
	0xA6, 0x77, 0x72, 0xF8, 0xEB, 0x75, 0x4B, 0x0A,
	0x31, 0x44, 0x50, 0xB4, 0x8F, 0xED, 0x1F, 0x1A,
	0xDB, 0x99, 0x8D, 0x33, 0x9F, 0x11, 0x83, 0x14,
	};

/* Basic MD2 step. Transforms digest based on data */

void MD2Transform( MD2_INFO *md2Info, BYTE *data )
	{
	BYTE intermediate[ MD2_DATASIZE * 3 ], tmp = 0;
	int i;

	/* Form the encryption block from the current MD, the next chunk of the
	   message, and the XOR of the MD and message chunk */
	for( i = 0; i < MD2_DATASIZE; i++ )
		{
		BYTE stateTmp = md2Info->state[ i ], dataTmp = data[ i ];

		intermediate[ i ] = stateTmp;
		intermediate[ i + MD2_DATASIZE ] = dataTmp;
		intermediate[ i + ( MD2_DATASIZE * 2 ) ] = stateTmp ^ dataTmp;
		}

	/* Make 18 passes over the intermediate data block.  We unrol the inner
	   loop a bit for speed */
	tmp = 0;
	for( i = 0; i < 18; i++ )
		{
		int j;

		for( j = 0; j < 48; j += 16 )
			{
			tmp = intermediate[ j +  0 ] ^= pi[ tmp ];
			tmp = intermediate[ j +  1 ] ^= pi[ tmp ];
			tmp = intermediate[ j +  2 ] ^= pi[ tmp ];
			tmp = intermediate[ j +  3 ] ^= pi[ tmp ];
			tmp = intermediate[ j +  4 ] ^= pi[ tmp ];
			tmp = intermediate[ j +  5 ] ^= pi[ tmp ];
			tmp = intermediate[ j +  6 ] ^= pi[ tmp ];
			tmp = intermediate[ j +  7 ] ^= pi[ tmp ];
			tmp = intermediate[ j +  8 ] ^= pi[ tmp ];
			tmp = intermediate[ j +  9 ] ^= pi[ tmp ];
			tmp = intermediate[ j + 10 ] ^= pi[ tmp ];
			tmp = intermediate[ j + 11 ] ^= pi[ tmp ];
			tmp = intermediate[ j + 12 ] ^= pi[ tmp ];
			tmp = intermediate[ j + 13 ] ^= pi[ tmp ];
			tmp = intermediate[ j + 14 ] ^= pi[ tmp ];
			tmp = intermediate[ j + 15 ] ^= pi[ tmp ];
			}

		tmp = ( tmp + i ) & 0xFF;
		}

	/* Save the new state */
	memcpy( md2Info->state, intermediate, MD2_DIGESTSIZE );

	/* Update the checksum */
	tmp = md2Info->checksum[ MD2_DATASIZE - 1 ];
	for( i = 0; i < MD2_DATASIZE; i++ )
		tmp = md2Info->checksum[ i ] ^= pi[ data[ i ] ^ tmp ];

	/* Clean up */
	zeroise( intermediate, MD2_DATASIZE * 3 );
	}

/****************************************************************************
*																			*
*							MD2 Support Routines							*
*																			*
****************************************************************************/

/* The routine md2Initial initializes the message-digest context md2Info */

void md2Initial( MD2_INFO *md2Info )
	{
	/* Clear all fields */
	memset( md2Info, 0, sizeof( MD2_INFO ) );
	}

/* The routine md2Update updates the message-digest context to account for
   the presence of each of the characters buffer[ 0 .. count-1 ] in the
   message whose digest is being computed */

void md2Update( MD2_INFO *md2Info, BYTE *buffer, int count )
	{
	int dataCount = md2Info->length;

	/* Handle simple case of no data */
	if( !count )
		return;

	/* Update the overall byte count mod MD2_DATASIZE */
	md2Info->length = ( md2Info->length + count ) % MD2_DATASIZE;

	/* If there's any leftover data from a previous call, process it now */
	if( dataCount )
		{
		int bytesLeft = MD2_DATASIZE - dataCount;

		/* If there's enough new data to build a chunk to process, do so
		   now */
		if( count >= bytesLeft )
			{
			memcpy( md2Info->data + dataCount, buffer, bytesLeft );
			MD2Transform( md2Info, md2Info->data );
			buffer += bytesLeft;
			count -= bytesLeft;
			}
		else
			{
			/* Save the input for later */
			memcpy( md2Info->data + dataCount, buffer, count );
			return;
			}
		}

	/* Rumble through the input in MD2_DATASIZE chunks */
	while( count >= MD2_DATASIZE )
		{
		MD2Transform( md2Info, buffer );
		buffer += MD2_DATASIZE;
		count -= MD2_DATASIZE;
		}

	/* Save the remaining input for later */
	memcpy( md2Info->data, buffer, count );
	}

/* Final wrapup - pad to a multiple of MD2_DATASIZE bytes and process */

void md2Final( MD2_INFO *md2Info )
	{
	int i, pad;

	/* Pad the message out to a multiple of 16 bytes and transform.  The
	   padding character is the number of padding bytes necessary */
	pad = MD2_DATASIZE - md2Info->length;
	for( i = md2Info->length; i < MD2_DATASIZE; i++ )
		md2Info->data[ i ] = pad;
	MD2Transform( md2Info, md2Info->data );

	/* Add the message checksum and transform */
	memcpy( md2Info->data, md2Info->checksum, MD2_DATASIZE );
	MD2Transform( md2Info, md2Info->data );

	md2Info->done = TRUE;
	}
