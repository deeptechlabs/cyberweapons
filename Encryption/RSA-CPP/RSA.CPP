#include "rsa.hpp"

class prime_factory
{
  unsigned np;
  unsigned *pl;
  public:
  prime_factory();
  ~prime_factory();
  vlong find_prime( vlong & start );
};

// prime factory implementation

static int is_probable_prime( const vlong &p )
{
  // Test based on Fermats theorem a**(p-1) = 1 mod p for prime p
  // For 1000 bit numbers this can take quite a while
  const rep = 4;
  const unsigned any[rep] = { 2,3,5,7 };
  for ( unsigned i=0; i<rep; i+=1 )
    if ( modexp( any[i], p-1, p ) != 1 )
      return 0;
  return 1;
}

prime_factory::prime_factory()
{
  np = 0;
  unsigned NP = 200;
  pl = new unsigned[NP];

  // Initialise pl
  unsigned SS = 8*NP; // Rough estimate to fill pl
  char * b = new char[SS+1]; // one extra to stop search
  for (unsigned i=0;i<=SS;i+=1) b[i] = 1;
  unsigned p = 2;
  while (1)
  {
    // skip composites
    while ( b[p] == 0 ) p += 1;
    if ( p == SS ) break;
    pl[np] = p;
    np += 1;
    if ( np == NP ) break;
    // cross off multiples
    unsigned c = p*2;
    while ( c < SS )
    {
      b[c] = 0;
      c += p;
    }
    p += 1;
  }
  delete [] b;
}

prime_factory::~prime_factory()
{
  delete [] pl;
}

vlong prime_factory::find_prime( vlong & start )
{
  unsigned SS = 1000; // should be enough unless we are unlucky
  char * b = new char[SS]; // bitset of candidate primes
  unsigned tested = 0;
  while (1)
  {
    unsigned i;
    for (i=0;i<SS;i+=1)
      b[i] = 1;
    for (i=0;i<np;i+=1)
    {
      unsigned p = pl[i];
      unsigned r = start % p; // not as fast as it should be - could do with special routine
      if (r) r = p - r;
      // cross off multiples of p
      while ( r < SS )
      {
        b[r] = 0;
        r += p;
      }
    }
    // now test candidates
    for (i=0;i<SS;i+=1)
    {
      if ( b[i] )
      {
        tested += 1;
        if ( is_probable_prime(start) )
          return start;
      }
      start += 1;
    }
  }
  delete [] b;
}

static vlong from_str( const char * s )
{
  vlong x = 0;
  while (*s)
  {
    x = x * 256 + (unsigned char)*s;
    s += 1;
  }
  return x;
}

void private_key::create( const char * r1, const char * r2 )
{
  // Choose primes
  {
    prime_factory pf;
    p = pf.find_prime( from_str(r1) );
    q = pf.find_prime( from_str(r2) );
    if ( p > q ) { vlong tmp = p; p = q; q = tmp; }
  }
  // Calculate public key
  {
    m = p*q;
    e = 50001; // must be odd since p-1 and q-1 are even
    while ( gcd(p-1,e) != 1 || gcd(q-1,e) != 1 ) e += 2;
  }
}

vlong public_key::encrypt( const vlong& plain )
{
  return modexp( plain, e, m );
}

vlong private_key::decrypt( const vlong& cipher )
{
  // Calculate values for performing decryption
  // These could be cached, but the calculation is quite fast
  vlong d = modinv( e, (p-1)*(q-1) );
  vlong u = modinv( p, q );
  vlong dp = d % (p-1);
  vlong dq = d % (q-1);

  // Apply chinese remainder theorem
  vlong a = modexp( cipher % p, dp, p );
  vlong b = modexp( cipher % q, dq, q );
  if ( b < a ) b += q;
  return a + p * ( ((b-a)*u) % q );
}

