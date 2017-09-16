/* combinedLcs.c - Combined linear congruential sequence generators.
Version of 93.06.17.
*/

/***********************************************************************
 * combinedLCG returns a pseudorandom real value in the range (0,1).
 * It combines linear congruential generators with periods of
 * 2^31-85 and 2^31-249, and has a period that is the product
 * of these two prime numbers.
 * In general, initLCG should be called before this function is used.
 * This implementation requires that a "long" be 32 bits long.
 * MODMULT(a,b,c,m,s) computes s*b mod m, provided that m=a*b+c and
 * 0 <= c < m. The computation is performed in such a way as to avoid
 * overflowing the available word length.
 ***********************************************************************/
static long s1 = 1 ;
static long s2 = 1 ;
#define MODMULT(a,b,c,m,s) q = s/a; s = b*(s-a*q) - c*q; if (s<0) s+=m;
double combinedLCG( void )
{
  long q ;
  long z ;

  MODMULT( 53668, 40014, 12211, 2147483563L, s1 )
  MODMULT( 52774, 40692, 3791,  2147483399L, s2 )
  z = s1 - s2 ;
  if ( z < 1 )
    z += 2147483562 ;
  return z * 4.656613e-10 ;
}

void initLCG( long InitS1, long InitS2 )
{
  s1 = InitS1 ;
  s2 = InitS2 ;
}

----------------------------------------------------------------------

/***********************************************************************
 * combinedLCG returns a pseudorandom real value in the range (0,1).
 * It combines linear congruential generators with periods of
 * 2^15-405, 2^15-1041 and 2^15-1111, and has a period that is the
 * product of these three prime numbers.
 * In general, initLCG should be called before this function is used.
 * This implementation requires that a "int" be 16 bits long.
 ***********************************************************************/
static int s1 = 1 ;
static int s2 = 1 ;
static int s3 = 1 ;
#define MODMULT(a,b,c,m,s) q = s/a; s = b*(s-a*q) - c*q; if (s<0) s+=m;
double combinedLCG( void )
{
  int q ;
  int z ;

  MODMULT( 206, 157, 21,  32363, s1 )
  MODMULT( 217, 146, 45,  31727, s2 )
  MODMULT( 222, 142, 133, 31657, s3 )
  z = s1 - s2 ;
  if ( z > 706 )
    z -= 32362 ;
  z += s3 ;
  if ( z < 1 )
    z += 32362 ;
  return z * 3.0899e-5 ;
}

void initLCG( int InitS1, int InitS2, InitS3 )
{
  s1 = InitS1 ;
  s2 = InitS2 ;
  s3 = InitS3 ;
}

