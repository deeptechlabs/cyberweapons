/********************************************************************\
*                                                                    *
* C specification of the threeway block cipher                       *
*                                                                    *
\********************************************************************/
/*file i/o main function by Pate Williams 1996*/

#include <ctype.h>
#include <stdio.h>
#include <process.h>
#include <string.h>
#include <time.h>

#define   STRT_E   0x0b0b /* round constant of first encryption round */
#define   STRT_D   0xb1b1 /* round constant of first decryption round */
#define     NMBR       11 /* number of rounds is 11                   */

#define   BLK_SIZE     12 /*number of bytes per block*/

typedef   unsigned long int  word32 ;
                 /* the program only works correctly if long = 32bits */

void mu(word32 *a)       /* inverts the order of the bits of a */
{
int i ;
word32 b[3] ;

b[0] = b[1] = b[2] = 0 ;
for( i=0 ; i<32 ; i++ )
   {
   b[0] <<= 1 ; b[1] <<= 1 ; b[2] <<= 1 ;
   if(a[0]&1) b[2] |= 1 ;
   if(a[1]&1) b[1] |= 1 ;
   if(a[2]&1) b[0] |= 1 ;
   a[0] >>= 1 ; a[1] >>= 1 ; a[2] >>= 1 ;
   }

a[0] = b[0] ;      a[1] = b[1] ;      a[2] = b[2] ;
}

void gamma(word32 *a)   /* the nonlinear step */
{
word32 b[3] ;

b[0] = a[0] ^ (a[1]|(~a[2])) ;
b[1] = a[1] ^ (a[2]|(~a[0])) ;
b[2] = a[2] ^ (a[0]|(~a[1])) ;

a[0] = b[0] ;      a[1] = b[1] ;      a[2] = b[2] ;
}

void theta(word32 *a)    /* the linear step */
{
word32 b[3];

b[0] = a[0] ^  (a[0]>>16) ^ (a[1]<<16) ^     (a[1]>>16) ^ (a[2]<<16) ^
               (a[1]>>24) ^ (a[2]<<8)  ^     (a[2]>>8)  ^ (a[0]<<24) ^
               (a[2]>>16) ^ (a[0]<<16) ^     (a[2]>>24) ^ (a[0]<<8)  ;
b[1] = a[1] ^  (a[1]>>16) ^ (a[2]<<16) ^     (a[2]>>16) ^ (a[0]<<16) ^
               (a[2]>>24) ^ (a[0]<<8)  ^     (a[0]>>8)  ^ (a[1]<<24) ^
               (a[0]>>16) ^ (a[1]<<16) ^     (a[0]>>24) ^ (a[1]<<8)  ;
b[2] = a[2] ^  (a[2]>>16) ^ (a[0]<<16) ^     (a[0]>>16) ^ (a[1]<<16) ^
               (a[0]>>24) ^ (a[1]<<8)  ^     (a[1]>>8)  ^ (a[2]<<24) ^
               (a[1]>>16) ^ (a[2]<<16) ^     (a[1]>>24) ^ (a[2]<<8)  ;

a[0] = b[0] ;      a[1] = b[1] ;      a[2] = b[2] ;
}

void pi_1(word32 *a)
{
a[0] = (a[0]>>10) ^ (a[0]<<22);
a[2] = (a[2]<<1)  ^ (a[2]>>31);
}

void pi_2(word32 *a)
{
a[0] = (a[0]<<1)  ^ (a[0]>>31);
a[2] = (a[2]>>10) ^ (a[2]<<22);
}

void rho(word32 *a)    /* the round function       */
{
theta(a) ;
pi_1(a) ;
gamma(a) ;
pi_2(a) ;
}

void rndcon_gen(word32 strt,word32 *rtab)
{                           /* generates the round constants */
int i ;

for(i=0 ; i<=NMBR ; i++ )
   {
   rtab[i] = strt ;
   strt <<= 1 ;
   if( strt&0x10000 ) strt ^= 0x11011 ;
   }
}

void encrypt(word32 *a, word32 *k)
{
char i ;
word32 rcon[NMBR+1] ;

rndcon_gen(STRT_E,rcon) ;
for( i=0 ; i<NMBR ; i++ )
   {
   a[0] ^= k[0] ^ (rcon[i]<<16) ;
   a[1] ^= k[1] ;
   a[2] ^= k[2] ^ rcon[i] ;
   rho(a) ;
   }
a[0] ^= k[0] ^ (rcon[NMBR]<<16) ;
a[1] ^= k[1] ;
a[2] ^= k[2] ^ rcon[NMBR] ;
theta(a) ;
}

void decrypt(word32 *a, word32 *k)
{
char i ;
word32 ki[3] ;          /* the `inverse' key             */
word32 rcon[NMBR+1] ;   /* the `inverse' round constants */

ki[0] = k[0] ; ki[1] = k[1] ; ki[2] = k[2] ;
theta(ki) ;
mu(ki) ;

rndcon_gen(STRT_D,rcon) ;

mu(a) ;
for( i=0 ; i<NMBR ; i++ )
   {
   a[0] ^= ki[0] ^ (rcon[i]<<16) ;
   a[1] ^= ki[1] ;
   a[2] ^= ki[2] ^ rcon[i] ;
   rho(a) ;
   }
a[0] ^= ki[0] ^ (rcon[NMBR]<<16) ;
a[1] ^= ki[1] ;
a[2] ^= ki[2] ^ rcon[NMBR] ;
theta(a) ;
mu(a) ;
}

void main(int argc, char *argv[])
{
  char key[128], *kp = key;
  double time;
  int c, command, k, left, len;
  long i, length, number;
  FILE *inp, *out;
  clock_t time0 = clock();
  word32 buffer[12], word_key[3];

  if (argc != 5)
  {
    printf("usage: %s inp_file out_file x key\n\n", argv[0]);
    printf("where x is d for decrypt or x is e for encrypt,\n");
    printf("and the key is twelve characters\n");
    exit(1);
  }
  inp = fopen(argv[1], "rb");
  if (!inp)
  {
    printf("*error*\ncould not open input file %s\n", argv[1]);
    exit(1);
  }
  out = fopen(argv[2], "wb");
  if (!out)
  {
    printf("*error*\ncould not open input file %s\n", argv[2]);
    exit(1);
  }
  command = tolower(argv[3][0]);
  if (command != 'd' && command != 'e')
  {
    printf("*error*\nillegal function indicator %c\n", argv[3][0]);
    exit(1);
  }
  strcpy(key, argv[4]);
  len = strlen(key);
  if (len < 12)
    for (k = len; k < 12; k++) key[k] = ' ';
  key[12] = '\0';
  memcpy(word_key, key, 12);
  fseek(inp, 0, SEEK_END);
  length = ftell(inp);
  fseek(inp, 0, SEEK_SET);
  number = length / BLK_SIZE;
  left = (int) (length % BLK_SIZE);
  if (command == 'd')
    for (i = 0; i < number; i++)
    {
      fread(buffer, BLK_SIZE, 1, inp);
      decrypt(buffer, word_key);
      fwrite(buffer, BLK_SIZE, 1, out);
    }
  else
    for (i = 0; i < number; i++)
    {
      fread(buffer, BLK_SIZE, 1, inp);
      encrypt(buffer, word_key);
      fwrite(buffer, BLK_SIZE, 1, out);
    }
  for (k = 0; k < left; k++)
  {
    c = fgetc(inp);
    c ^= *kp++;
    fputc(c, out);
  }
  time = (clock() - time0) / (double) CLK_TCK;
  printf("total time required  = %f seconds\n", time);
  if (time != 0.0)
    printf("kilobytes per second = %f\n", length / (time * 1024.0));
  else
    printf("total bytes processed = %ld\n", length);
}
}
