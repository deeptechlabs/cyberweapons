/* lsfr.c - Two implementations of a 32-bit linear-feedback shift register
	based on polynomial x^32+x^7+x^5+x^3+x^2+x+1.
Version of 93.07.02.
*/

/***********************************************************************
 * The following implementation of LFSR is easy to read (in that the
 * correspondance to the traditional definition of an LFSR is obvious),
 * but is much slower than the alternative implementation presented
 * later. (The problem of proving the equivalence of these two
 * implementations is presented as an exercise in Knuth, second edition,
 * volume 2, section 3.2.2, exercise 16.)
 **********************************************************************/

int LFSRslow( void )
{
  static unsigned long ShiftRegister = 1 ;      /* Anything but 0. */

  ShiftRegister = (((  ( ShiftRegister >> 7 )
		     ^ ( ShiftRegister >> 5 )
		     ^ ( ShiftRegister >> 3 )
		     ^ ( ShiftRegister >> 2 )
		     ^ ( ShiftRegister >> 1 )
		     ^ ShiftRegister )
		     & 1 ) << 31 )
		   | ( ShiftRegister >> 1 ) ;
  return ShiftRegister & 1 ;
}

/**********************************************************************
 * The following implementation of LFSR performs exactly as the
 * preceding one, but runs substantially faster.
 **********************************************************************/

int LFSRfast( void )
{
  static unsigned long ShiftRegister = 1 ;      /* Anything but 0. */

  if ( ( ShiftRegister & 0x80000000 ) == 0 )
    {
      ShiftRegister <<= 1 ;
      return 0 ;
    }
  ShiftRegister = ( ShiftRegister << 1 ) ^ 0xaf ;
  return 1 ;
}

