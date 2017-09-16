/*
  pegwit by George Barwood <george.barwood@dial.pipex.com>
  100% Public Domain
  clearsigning code by Mr. Tines <tines@windsong.demon.co.uk>
  also the filter mode support.
*/

#include <string.h>
#include <stdio.h>
#include <time.h>
#include <ctype.h>

#include "ec_crypt.h"
#include "sha1.h"
#include "square.h"
#include "sqcts.h"
#include "binasc.h"

#if defined(__BORLANDC__) && defined(__MSDOS__)
#include <dos.h>
unsigned _stklen = 32768u;
#endif


const char manual /*:)*/ [] = 
  "Pegwit v8.7\n"
  "Usage (init/encrypt/decrypt/sign/verify) :\n"
  "-i <secret-key >public-key\n"
  "-e public-key plain cipher <random-junk\n"
  "-d cipher plain <secret-key\n"
  "-s plain <secret-key >signature\n"
  "-v public-key plain <signature\n"
  "-E plain cipher <key\n"
  "-D cipher plain <key\n"
  "-S text <secret-key >clearsigned-text\n"
  "-V public-key clearsigned-text >text\n"
  "-f[operation] [type pegwit -f for details]\n";
const char filterManual [] =
  "Pegwit [filter sub-mode]\n"
  "Usage (encrypt/decrypt/sign/verify) :\n"
  "-fe public-key random-junk <plain >ascii-cipher\n"
  "-fd secret-key <ascii-cipher >plain\n"
  "-fE key <plain >ascii-cipher\n"
  "-fD key <ascii-cipher >plain\n"
  "-fS secret-key <text >clearsigned-text\n"
  "-fV public-key <clearsigned-text >text\n";


const char pubkey_magic [] = "pegwit v8 public key =";
const char err_output [] = "Pegwit, error writing output, disk full?";
const char err_open_failed [] = "Pegwit, error : failed to open ";
const char err_bad_public_key [] = "Pegwit, error : public key must start with \"";
const char err_signature [] = "signature did not verify\a\a\a\n";
const char err_decrypt [] = "decryption failed\a\a\a\n";

const char begin_clearsign [] = "###\n";
const char end_clearsign [] = "### end pegwit v8 signed text\n";
const char end_ckarmour [] = "### end pegwit v8.7 -fE encrypted text\n";
const char end_pkarmour [] = "### end pegwit v8.7 -fe encrypted text\n";
const char escape [] = "## ";
const char warn_long_line [] = 
  "Very long line - > 8k bytes.  Binary file?\n"
  "Clearsignature dubious\a\a\a\n";
const char warn_control_chars [] = 
  "Large number of control characters.  Binary file?\n"
  "Clearsignature dubious\a\a\a\n";
const char err_clearsig_header_not_found [] = 
  "Clearsignature header \"###\" not found\a\a\a\n";


#define BPB (SQUARE_BLOCKSIZE) /* 16 */
#define NB  ((GF_M+1+7)/8)

void hash_process_file( hash_context * c, FILE * f_inp, unsigned barrel )
{
  unsigned n;
  unsigned char buffer[0x4000];
  while (1)
  {
    n = fread( buffer, 1, 0x4000, f_inp ); /* note: no error check */
    if (n==0) break;
    {
      unsigned j;
      for ( j=0; j<barrel; j+=1 )
      {
        hash_process( c+j, buffer, n );
      }
    }
    if (n < 0x4000) break;
  }
  memset( buffer, sizeof(buffer), 0 );
  fseek( f_inp, 0, SEEK_SET );
}

int downcase(char c)
{
      if(isascii(c)) if(isupper(c)) return tolower(c);
      return c;
}

int case_blind_compare(const char *a, const char *b)
{
    while(*a && *b)
    {
        if(downcase(*a) < downcase(*b)) return -1;
        if(downcase(*a) > downcase(*b)) return 1;
        a += 1;
        b += 1;
    }
    if(*a) return 1;
    if(*b) return -1;
    return 0;
}

void hash_process_ascii( hash_context * c, FILE * f_inp,
  FILE * f_out, unsigned barrel, int write)
{
  unsigned n;
  unsigned char buffer[0x4000], *begin;
  unsigned long bytes=0, control=0;

  while (1)
  {
      unsigned i;
      
      fgets((char*)buffer, 0x4000, f_inp);  /* EOL -> \n */
      if(feof(f_inp)) break;

      n = strlen((char*)buffer);
      begin = buffer;

      if(n > 0x2000)
      {
        fputs( warn_long_line, f_out );
      }

      bytes += n;
      for(i=0; i<n; ++i)
      {
        if(buffer[i] >= 0x7F) ++control;
        if(buffer[i] < ' ' && buffer[i] != '\n' && buffer[i] != '\r'
          && buffer[i] != '\t') ++control;
      }

      if(write)
      {
        if (!strncmp( (char*)buffer, escape, 2 ) ||
            !case_blind_compare((char*)buffer, "from") )
        {
          fputs( escape, f_out );
        }
        fputs( (char*)buffer, f_out);
      }
      else
      {
        if(!strncmp((char*)buffer, escape, 3)) {n-=3, begin+=3;}
        else if(!strncmp((char*)buffer, end_clearsign, 3)) break; /* must be end of packet */
        fputs((char*)begin, f_out);
      }

      for ( i=0; i<barrel; ++i )
      {
        hash_process( c+i, begin, n );
      }
  }
  if(control*6 > bytes)
  {
    fputs( warn_control_chars, stderr );
  }

  memset( buffer, sizeof(buffer), 0 );
}

typedef struct /* Whole structure will be hashed */
{
  unsigned count;        /* Count of words */
  word32 seed[2+HW*3];   /* Used to crank prng */
} prng;

void prng_init( prng * p )
{
  memset( p, 0, sizeof(*p) );
}

void prng_set_secret( prng * p, FILE * f_key )
{
  hash_context c[1];
  hash_initial( c );
  hash_process_file( c, f_key, 1 );
  hash_final( c, p->seed+1 );
  p->count = 1+HW;  
}

void prng_init_mac(hash_context c[2])
{
  /* Use 2 barrels to be conservative */
  unsigned char b;
  for ( b=0; b<2; ++b )
  {
    hash_initial( c+b );
    hash_process( c+1, &b, 1 ); /* uninitialised on first pass */
  }
}

void prng_set_mac( prng * p, FILE * f_inp, int barrel )
{
  /* barrel should be 1 or 2 */
  unsigned char b;
  hash_context c[2];
  for ( b=0; b<barrel; b+=1 )
  {
    hash_initial( c+b );
    if ( b==1 ) hash_process( c+1, &b, 1 );
  }
  hash_process_file( c, f_inp, barrel );
  for ( b=0; b<barrel; b+=1 )
  {
    hash_final( c, p->seed+1+HW*(b+1) );
  }
  p->count = 1 + (barrel+1)*HW;
}

void clearsign( prng * p, FILE * f_inp, FILE * f_out )
{
  hash_context c[2];

  prng_init_mac(c);
  fputs(begin_clearsign,f_out);
  hash_process_ascii( c, f_inp, f_out, 2, 1 );
  fputs(end_clearsign,f_out);
  hash_final( c, p->seed+1+HW );
  hash_final( c, p->seed+1+2*HW );
  p->count = 1 + 3*HW;
}

int position(FILE  * f_inp) /* scan ascii file for ### introducer */
{
  while(!feof(f_inp))
  {
      char buffer[1024];
      fgets(buffer, 1024, f_inp);
      if(!strncmp(buffer, begin_clearsign, 3)) break;
  }
  if(feof(f_inp))
  {
    fputs( err_clearsig_header_not_found, stderr );
    return 0;
  }
  return 1;
}

int readsign( prng * p, FILE * f_inp, FILE * f_out )
{
  hash_context c[2];
  prng_init_mac(c);

  if(!position(f_inp)) return 1;
  hash_process_ascii( c, f_inp, f_out, 2, 0 );
  hash_final( c, p->seed+1+HW );
  hash_final( c, p->seed+1+2*HW );
  p->count = 1 + 3*HW;

  return 0;
}

void prng_set_time( prng * p )
{
  p->seed[1+3*HW] = (word32) time(0);
  p->count = 2 + 3*HW;
}

word32 prng_next( prng * p )
{
  word32 tmp[HW];
  byte buffer[ ( 3*HW  + 2 ) * 4 ];
  unsigned i,j;
  hash_context c;

  p->seed[0] += 1;
  for ( i = 0; i < p->count; i+=1 )
  {
    for ( j = 0; j < 4; j += 1 )
    {
      buffer[ i*4 + j ] = (byte) ( p->seed[i] >> (j*8) );
    }
  }
  
  hash_initial( &c );
  hash_process( &c, buffer, p->count*4 );
  hash_final( &c, tmp );
  memset( buffer, 0, sizeof(buffer) );
  return tmp[0];
}

void prng_to_vlong( prng * p, vlPoint V )
{
  unsigned i;
  V[0] = 15; /* 240 bits */
  for (i=1;i<16;i+=1)
    V[i] = (unsigned short) prng_next( p );
}

void hash_to_vlong( word32 * mac, vlPoint V )
{
  unsigned i;
  V[0] = 15; /* 240 bits */
  for (i=0;i<8;i+=1)
  {
    word32 x = mac[i];
    V[i*2+1] = (word16) x;
    V[i*2+2] = (word16) (x>>16);
  }
}

void get_vlong( FILE *f, vlPoint v )
{
  unsigned u;
  vlPoint w;
  vlClear (v);
  w[0] = 1;
  while (1)
  {
    u = fgetc( f );
    if ( u >= '0' && u <= '9' )
      u -= '0';
    else if ( u >= 'a' && u <= 'z' )
      u -= 'a' - 10;
    else if ( u >= 'A' && u <= 'Z' )
      u -= 'A' - 10;
    else if ( u <= ' ' )
      continue;
    else
      break;
    vlShortLshift (v, 4);
    w[1] = (word16) u;
    vlAdd (v, w);
  }
}

void get_vlong_a( FILE *f, vlPoint v )
{
  unsigned i=0;
  char buffer[256], u;

  vlPoint w;
  vlClear (v);
  w[0] = 1;
  buffer[0]=0;
  fgets(buffer, 256, f);

  while ((u = buffer[i++]) != 0)
  {
    if ( u >= '0' && u <= '9' )
      u -= '0';
    else if ( u >= 'a' && u <= 'z' )
      u -= 'a' - 10;
    else if ( u >= 'A' && u <= 'Z' )
      u -= 'A' - 10;
    else if ( u <= ' ' )
      continue;
    else
      break;
    vlShortLshift (v, 4);
    w[1] = (word16) u;
    vlAdd (v, w);
  }
}

const char hex[16] = "0123456789abcdef";

void put_vlong( vlPoint v )
{
  unsigned i,j;
  for (i = v[0]; i > 0; i--) 
  {
    unsigned x = v[i];
    for (j=0;j<4;j+=1)
      putchar( hex[ (x >> (12-4*j)) % 16 ] );
  }
}

void put_binary_vlong (FILE *f, vlPoint v)
{
  unsigned n = NB;
  while (n--)
  {
    if (v[0] == 0) v[1] =  0;
    fputcPlus (v[1] & 0xff, f);
    vlShortRshift (v, 8);
  }
}

void get_binary_vlong(FILE *f, vlPoint v)
{
  byte u[NB];
  vlPoint w;
  unsigned n = NB;
  freadPlus(u, 1, NB, f);
  vlClear (v); w[0] = 1;
  while (n--)
  {
    vlShortLshift (v, 8);
    w[1] = u[n];
    vlAdd (v, w);
  }
}

#define BIG_BLOCK_SIZE 0x1000
typedef word32 big_buf[1+BIG_BLOCK_SIZE/4]; /* Use word32 to force alignment */
/* 1 extra word to cope with expansion */

void vlong_to_square_block( const vlPoint V, squareBlock key )
{
  vlPoint v;
  unsigned j;
  vlCopy (v, V);
  for (j = 0; j < BPB; j++)
  {
    if (v[0] == 0) v[1] = 0;
    key[j] = (byte)v[1];
    vlShortRshift (v, 8);
  }
}

void increment( squareBlock iv )
{
  int i = 0;
  while (iv[i]==0xff) iv[i++] = 0;
  iv[i] += 1;
}

int sym_encrypt( vlPoint secret, FILE * f_inp, FILE * f_out )
{
  squareBlock key,iv;
  squareCtsContext ctx;
  big_buf buffer;

  int n,err = 0;
  byte pad;

  memset( iv, 0, sizeof(iv) );
  vlong_to_square_block (secret, key);
	squareCtsInit( &ctx, key );
  pad = 0;
  while (n = fread( buffer, 1, BIG_BLOCK_SIZE, f_inp ) )
  {    
    if ( n < BIG_BLOCK_SIZE )
    {
      pad = 0;
      if (n<BPB)
        pad = 17-n;
      else if (n&1)
        pad = 2;
      memset( n+(byte*)buffer, pad, pad );
      n += pad;
    }
    squareCtsSetIV( &ctx, iv );
    increment(iv);
    squareCtsEncrypt( &ctx, (byte*)buffer, n );
    {
      int written = fwritePlus( buffer,1,n,f_out );
      if ( written != n )
      {
        fputs( err_output, stderr );   
        err = 1;
        break;
      }
    }    
  }

  squareCtsFinal( &ctx );
  memset( key, 0, sizeof(key) );
  return err;
}

int sym_decrypt( vlPoint secret, FILE * f_inp, FILE * f_out)
{
  squareBlock key,iv;
  big_buf b1,b2;
  byte * buf1 = (byte*)b1, * buf2 = (byte*)b2;
  squareCtsContext ctx;
  int err = 0, n = 0;

  memset(iv,0,sizeof(iv));
  vlong_to_square_block( secret, key );
	squareCtsInit( &ctx, key );

  while (1)
  {
    int i = 0;
    if ( n == 0 || n == BIG_BLOCK_SIZE ) 
      i = freadPlus( buf1, 1, BIG_BLOCK_SIZE, f_inp );
    if (n)
    {
      if ( n < BPB )
      {
        decrypt_error:
        fputs( err_decrypt, stderr );
        err = 1;
        break;
      }

      if ( i == 1 )
      {
        n += 1;
        buf2[BIG_BLOCK_SIZE] = buf1[0];
        i = 0;
      }
      squareCtsSetIV( &ctx, iv );
      increment( iv );
      squareCtsDecrypt( &ctx, buf2, n );

      if ( n & 1 )
      {
        byte pad = buf2[n-1];
        /* Check pad bytes are as expected */
        if ( pad < 1 || pad > BPB ) goto decrypt_error; 
        n -= pad;
        {
          int j;
          for (j=0;j<pad;j+=1)
            if ( buf2[n+j] != pad ) goto decrypt_error;
        }
      }
      {
        int written = fwrite( buf2, 1, n, f_out );
        if ( written != n )
        {
          fputs( err_output, stderr );   
          err = 1;
          break;
        }
      }
    }
    if ( i == 0 ) break;
    { byte * tmp = buf1; buf1=buf2; buf2 = tmp; } /* swap */
    n = i;
  }
  memset( key, 0, sizeof(key) );
  squareCtsFinal( &ctx );
  return err;
}

int do_operation( FILE * f_key, FILE * f_inp, FILE * f_out, FILE * f_sec, int operation )
{
  prng p;
  vlPoint pub,secret,session,mac,msg; 
  cpPair sig;
  int err = 0;
  /* Initialise the prng and calculate keys */

  prng_init( &p );
  if ( operation == 'v' || operation == 'e' || 'V' == operation ) /* public key operations */
  {
    get_vlong( f_key, pub ); /* should be a validity check here */
    if ( operation == 'e' )
    {
      if ( f_sec ) prng_set_secret( &p, f_sec );
      prng_set_mac( &p, f_inp, 1 );
    }
  }
  else
  {
    setbuf(f_key,0); /* intention is to help security */
    prng_set_secret( &p, f_key );
    if ( operation == 'E' || operation == 'D' )
      hash_to_vlong( p.seed+1, secret );
    else
      prng_to_vlong( &p, secret );
  }

  if ( operation == 's' || operation == 'v' )
  {
    prng_set_mac( &p, f_inp, 2 );
    hash_to_vlong( p.seed+1+HW, mac );
  }
  if('S' == operation)
  {
    clearsign( &p, f_inp, f_out );
    hash_to_vlong( p.seed+1+HW, mac );
  }
  if('V' == operation)
  {
    if ( readsign( &p, f_inp, f_out ) )
      return 2; /* header not found */
    hash_to_vlong( p.seed+1+HW, mac );
  }


  /* Do operation */

  if ( operation == 'E' )
  {
    if(stdout == f_out) fputs(begin_clearsign,f_out);
    err = sym_encrypt( secret, f_inp, f_out );
    if(stdout == f_out)
    {
      if(!flushArmour(f_out)) return 3;
      fputs(end_ckarmour, f_out);
    }
  }
  else if ( operation == 'D' )
  {
    if(stdin == f_inp) if(!position(f_inp)) return 2;
    err = sym_decrypt( secret, f_inp, f_out );
  }
  else
  {
    gfInit();
    if ( operation == 'i' )
    {
      cpMakePublicKey( pub, secret );
      fputs( pubkey_magic, f_out);
      put_vlong( pub );
    }
    else if ( operation == 'e' )
    {
      if(stdout == f_out) fputs(begin_clearsign,f_out);
      prng_set_time( &p );
      prng_to_vlong( &p, session );
      cpEncodeSecret( pub, msg, session );
      put_binary_vlong( f_out, msg );
      err = sym_encrypt( session, f_inp, f_out );
      if(stdout == f_out)
      {
        if(!flushArmour(f_out)) return 3;
        fputs(end_pkarmour, f_out);
      }
    }
    else if ( operation == 'd')
    {
      if(stdin == f_inp) if(!position(f_inp)) return 2;
      get_binary_vlong( f_inp, msg );
      cpDecodeSecret( secret, msg, session );
      err = sym_decrypt( session, f_inp, f_out );
    } 
    else if ( operation == 's' || 'S' == operation)
    {                  
      do
      {
        prng_to_vlong( &p, session );
        cpSign( secret, session, mac, &sig );
      } while ( sig.r[0] == 0 );
      put_vlong( sig.s );
      if('S' == operation) fputs("\n", f_out); /* avoid word wrap */
      else fputs( ":", f_out );
      put_vlong( sig.r );
      if('S' == operation) fputs("\n", f_out); /* avoid word wrap */
    }
    else 
		{
		  if('v' == operation)
      {
        get_vlong( f_sec, sig.s );
        get_vlong( f_sec, sig.r );
			}
			else /* if( 'V' == operation) */
      {
        get_vlong_a( f_inp, sig.s );
        get_vlong_a( f_inp, sig.r );
		  }
      err = !cpVerify( pub, mac, &sig );
      if (err) 
			  fputs( err_signature, stderr );
    }
    gfQuit();
  }
  fflush(f_out);
  /* burn sensistive information */
  prng_init( &p );
  vlClear( secret );
  vlClear( session );
  return err;
}

FILE * chkopen( char * s, char * mode )
{
  FILE * result = fopen(s,mode);
  if (!result)
  {
    fputs( err_open_failed, stderr );
    fputs( s, stderr );
  }
  return result;
}

void burn_stack(void)
{  
  /* just in case any local burn code has been forgotten */
  /* size is just a fairly conservative guess */
  unsigned char x [ 20000 ];
  memset( x, 0, sizeof(x) );
}

#if !defined(LITTLE_ENDIAN) && !defined(BIG_ENDIAN)
  #if defined(_M_IX86) || defined(_M_I86) || defined(__alpha)
    #define LITTLE_ENDIAN
  #else
    #error "LITTLE_ENDIAN or BIG_ENDIAN must be defined"
	#endif
#endif

int main( unsigned argc, char * argv[] )
{
  int err, operation, filter=0;
  unsigned expect, arg_ix;
  FILE * f_key, * f_inp, * f_out, *f_sec;
  char openForRead [3] = "rb";
  char openForWrite [3] = "wb";
  char openKey[3] = "rb";

  static byte x[4] = {1,2,3,4};
	#ifdef LITTLE_ENDIAN
    if ( *(word32*)x != 0x04030201 )
  	{
	    fputs( "Porting error : need to define BIG_ENDIAN instead of LITTLE_ENDIAN\n", stderr );
			return 1;
    }
	#else
	  if ( *(word32*)x != 0x01020304 )
  	{
	    fputs( "Porting error : need to define LITTLE_ENDIAN instead of BIG_ENDIAN\n", stderr );
			return 1;
    }
  #endif

  if ( argc<2 || argv[1][0] != '-')
  {
    error:
    if(filter) goto filterError;
    fputs( manual, stderr );
    /* gfSelfTest(100);
    ecSelfTest(100);*/
    return 1;
  }
  operation = argv[1][1];

  if('f' == operation)
  {
      filter=1;
      operation = argv[1][2];
      if(0 == argv[1][2])
      {
         filterError:
         fputs(filterManual, stderr);
         return 1;
      }
      if (0 != argv[1][3]) goto error;
  }
  else if (argv[1][2] != 0 ) goto error;

  /* Check the number of arguments */
  expect = 0;

  if(!filter)
  {
    if ( operation == 'i' ) expect = 2;
    else if ( operation == 's' || 'S' == operation ) expect = 3;
    else if ( operation == 'd' || operation == 'v' || 'V' == operation ||
    operation == 'D' || operation == 'E' ) expect = 4;
    else if ( operation == 'e' ) expect = 5;
  }
  else
  {
    if('V' == operation || 'S' == operation || 'E' == operation ||
      'D' == operation || 'd' == operation ) expect = 3;
   else if ('e' == operation) expect = 4;
  }
  
  if ( argc != expect ) goto error;

  arg_ix = 2;

  f_key = stdin;
  if ( operation == 'e' || operation == 'v' || 'V' == operation || filter )
  {
    unsigned i, isPub = 1;

    if('S' == operation || 'd' == operation) openKey[1] = 0;

    f_key = chkopen( argv[arg_ix++], openKey );

    if (!f_key) return 1;
    if(filter && 'e' != operation && 'V' != operation) isPub = 0;

    for (i=0;isPub && pubkey_magic[i];i+=1)
    {
      if ( fgetc( f_key ) != pubkey_magic[i] )
      {
        fputs( err_bad_public_key, stderr );
        fputs( pubkey_magic, stderr );
        fputc( '"', stderr );
        return 1;
      }
    }
  }

  f_inp = stdin;
  f_out = stdout;

  if(!filter)
  {
    if('V' == operation || 'S' == operation)
      openForRead[1] = openForWrite[1] = 0;

    f_sec = 0;
    if('e' == operation || 'v' == operation) f_sec = stdin;
    if ( argc > arg_ix )
    {
      f_inp = chkopen( argv[arg_ix++], openForRead );
      if (!f_inp) return 1;
    }
    if ( argc > arg_ix )
    {
      f_out = chkopen( argv[arg_ix++], openForWrite );
      if (!f_out) return 1;
    }
  }
  else
  {
      f_sec = 0;
      if('e' == operation)
      {
        f_sec = chkopen( argv[arg_ix++], openForRead );
        if (!f_sec) return 1;
      }
  }

  err = do_operation( f_key, f_inp, f_out, f_sec, operation );

  burn_stack();
  burnBinasc();
  return err;
}

