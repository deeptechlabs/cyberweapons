class vlong // very long integer - can be used like long
{
public:
  // Standard arithmetic operators
  friend vlong operator +( const vlong& x, const vlong& y );
  friend vlong operator -( const vlong& x, const vlong& y );
  friend vlong operator *( const vlong& x, const vlong& y );
  friend vlong operator /( const vlong& x, const vlong& y );
  friend vlong operator %( const vlong& x, const vlong& y );
  vlong& operator +=( const vlong& x );
  vlong& operator -=( const vlong& x );

  // Standard comparison operators
  friend inline int operator !=( const vlong& x, const vlong& y ){ return x.cf( y ) != 0; }
  friend inline int operator ==( const vlong& x, const vlong& y ){ return x.cf( y ) == 0; }
  friend inline int operator >=( const vlong& x, const vlong& y ){ return x.cf( y ) >= 0; }
  friend inline int operator <=( const vlong& x, const vlong& y ){ return x.cf( y ) <= 0; }
  friend inline int operator > ( const vlong& x, const vlong& y ){ return x.cf( y ) > 0; }
  friend inline int operator < ( const vlong& x, const vlong& y ){ return x.cf( y ) < 0; }

  // Construction and conversion operations
  vlong ( unsigned x=0 );
  vlong ( const vlong& x );
  ~vlong();
  operator unsigned ();
  vlong& operator =(const vlong& x);

private:
  class vlong_value * value;
  int negative;
  int cf( const vlong x ) const;
  void docopy();
  friend class monty;
};

vlong modexp( const vlong & x, const vlong & e, const vlong & m ); // m must be odd
vlong gcd( const vlong &X, const vlong &Y ); // greatest common denominator
vlong modinv( const vlong &a, const vlong &m ); // modular inverse




