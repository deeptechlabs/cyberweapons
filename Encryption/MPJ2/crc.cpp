/* crc.cpp -- contains table based CCITT 16 bit CRC function.
*/

#define CRC_MASK           0xFFFFFFFFL
#define CRC32_POLYNOMIAL   0xEDB88320L

#include "def.h"
#include "crc.h"

unsigned long int *Ccitt32Table = NULL;

/****************************************************************************/

/*
 * This routine simply builds the coefficient table used to calculate
 * 32 bit CRC values throughout this program.  The 256 long word table
 * has to be set up once when the program starts.  Alternatively, the
 * values could be hard coded in, which would offer a miniscule improvement
 * in overall performance of the program.
 */

int CALLTYPE BuildCRCTable(void)
{
    int i;
    int j;
    unsigned long value;

    if (Ccitt32Table)
		return 0;
	else
		Ccitt32Table = new unsigned long int[256];
    if (Ccitt32Table == NULL)
      {
        return 1;
      }
    for ( i = 0; i <= 255 ; i++ ) {
	value = i;
	for ( j = 8 ; j > 0; j-- ) {
	    if ( value & 1 )
		value = ( value >> 1 ) ^ CRC32_POLYNOMIAL;
	    else
		value >>= 1;
	}
	Ccitt32Table[ i ] = value;
    }
  return 0;
}


void CALLTYPE crc32done(void)
  {
    if (Ccitt32Table)
      {
        delete Ccitt32Table;
        Ccitt32Table = NULL;
      }
  }

