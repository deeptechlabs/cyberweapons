#include <stdio.h>
#include <time.h>

#include "vlong.hpp"
#include "ncurve.hpp"

void decimal_print( vlong x )
{
  if ( x > 9 )
	  decimal_print(x/10);
	printf("%u", to_unsigned(x%10));
}

void hex_print( FILE * f, vlong x )
{
  int count = 0;

  fprintf( f, "\n\t 0x%04xU,", (x.bits()+15)/16 );
	while (x != 0)
	{
      fprintf( f, "%s0x%04xU,", count == 7 ? "\n\t " : " ", to_unsigned(x & 0xffff) );
      x >>= 16;
      count = (count + 1) & 7;
	}
}

// kludge get round C++ access rights
struct Xfield_element
{
  field * f;
  unsigned v[2*MAXK];
};

struct Xpoint
{ 
  curve * c;
  Xfield_element x,y;
};

void print_poly( FILE * f, unsigned * v )
{
  int count = 0;

  fprintf( f, "\t{0x%04xU,", v[0] );
  for (unsigned i=1;i<=v[0];i+=1) {
	  fprintf( f, "%s0x%04xU,", count == 7 ? "\n\t " : " ", v[i] );
	  count = (count + 1) & 7;
  }
  fprintf( f, "},\n" );
}

void print_point( FILE * f, const point & P )
{
  Xpoint * p = (Xpoint*)&P;
  print_poly( f, p->x.v );
  print_poly( f, p->y.v );
}
 
curve_parameter const cdata [] =
{
  #include "ncdatas.hpp"
};

unsigned const num_curve = sizeof(cdata)/sizeof(curve_parameter);

extern "C" int main(int argc, char * argv[])
{
  clock_t elapsed = -clock();
  FILE * f1 = fopen( "ec_param.c", "wt" );
  FILE * f2 = fopen( "ec_param.h", "wt" );

  fprintf( f1, "#include \"ec_vlong.h\"\n#include \"ec_curve.h\"\n\n");
	fprintf( f2, 
	"/*\n"
	"\tGF_M\tdimension of the large finite field (GF_M = GF_L*GF_K)\n"
	"\tGF_L\tdimension of the small finite field\n"
	"\tGF_K\tdegree of the large field reduction trinomial\n"
	"\tGF_T\tintermediate power of the reduction trinomial\n"
	"\tGF_RP\treduction polynomial for the small field (truncated)\n"
	"\tGF_NZT\telement of the large field with nonzero trace\n"
	"\tGF_TM0\tsize of trace mask\n"
	"\tGF_TM1\t1st nonzero element of trace mask\n"
	"\tGF_TM2\t2nd nonzero element of trace mask\n"
	"\tEC_B	scalar term of elliptic curve equation (y^2 + xy = x^3 + EC_B)\n"
  "*/\n\n"
  "#ifndef GF_M\n"
  "#define GF_M\t\t255 /* choose this value from the list below */\n"
  "#endif /* ?GF_M */\n"
	);

  unsigned prev_GF_M = 0;

  for ( unsigned ci=0; ci < num_curve; ci +=1 )
  {
  	full_curve_parameter a( cdata[ci] );
    curve C(a); 

	if (a.L*a.K == prev_GF_M) continue;
	prev_GF_M = a.L*a.K;
	if (ci==0) fprintf( f1, "\n#if" ); else fprintf( f1, "\n#elif" );
		
	fprintf( f1, " GF_M == %d\n\n", a.L*a.K );
    fprintf( f1, "const vlPoint prime_order = {" );
    hex_print( f1, a.p0 );
  	fprintf( f1, "\n}; /* prime_order */\n\n");

    fprintf( f1, "const ecPoint curve_point = {\n" );
	print_point( f1, C.PP );
	fprintf( f1, "}; /* curve_point */\n" );

    unsigned TM0 = (a.tm.bits() + a.L - 1)/a.L;
		unsigned TM1 = 0;
		unsigned TM2 = 0;
		{ 
		  for (unsigned i=0;i<a.L;i+=1)
			  TM1 = TM1*2 + 1;
		}
		TM1 = to_unsigned(a.tm) & TM1;
		if (TM0 > 1)
		{
		  vlong x = a.tm;
			x >>= a.L*(TM0-1);
		  TM2 = to_unsigned( x );
		}

	  if (ci==0) fprintf( f2, "\n#if" ); else fprintf( f2, "\n#elif" );
		fprintf( f2, " GF_M == %d\n\n", a.L*a.K );
		fprintf( f2, "#define GF_L\t%7d\n", a.L );
		fprintf( f2, "#define GF_K\t%7d\n", a.K );
		fprintf( f2, "#define GF_T\t%7d\n", a.T );
		fprintf( f2, "#define GF_RP\t0x%04xU\n", a.root );
		if ( (a.L*a.K) % 2 == 0 )
		{
      unsigned NZT = 1;
		  while ( (NZT & a.tm) == 0 ) NZT <<= 1;
		  fprintf( f2, "#define GF_NZT\t0x%04xU\n", NZT );
	  }
    
		
		fprintf( f2, "#define GF_TM0\t%7d\n", TM0 );
    fprintf( f2, "#define GF_TM1\t0x%04xU\n", TM1 );
    if (TM0 > 1) 
		  fprintf( f2, "#define GF_TM2\t0x%04xU\n", TM2 );

		fprintf( f2, "#define EC_B\t0x%04xU\n", a.b );

		printf("%d ",a.L*a.K);
	  
	}
  fprintf( f1, "\n#endif /* GF_M */\n" );
  
  fprintf( f2,
	  "\n#else\n\n"
		"#error \"The selected GF_M value is not acceptable\"\n\n"
    "#endif /* GF_M */\n"
	);

  elapsed += clock();
  printf ("Generation time: %.1f s.\n", (float)elapsed/CLOCKS_PER_SEC);

  return 0;
}
