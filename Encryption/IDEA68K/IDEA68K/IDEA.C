/* #define rasterAndTime          uncomment this line if you use raster files */

/******************************************************************************/
/*                                                                            */
/* I N T E R N A T I O N A L  D A T A  E N C R Y P T I O N  A L G O R I T H M */
/*                                                                            */
/******************************************************************************/
/* Author:       Richard De Moliner (demoliner@isi.ethz.ch)                   */
/*               Signal and Information Processing Laboratory                 */
/*               Swiss Federal Institute of Technology                        */
/*               CH-8092 Zuerich, Switzerland                                 */
/* Last Edition: 23 April 1992                                                */
/* System:       SUN SPARCstation, SUN cc C-Compiler, SUN-OS 4.1.1            */
/******************************************************************************\
NAME
     idea - encrypt and decrypt using IDEA

SYNOPSIS
     idea [ -e | -d ] [ -r ] [ -ecb | -cbcN | -cfbN | -ofbN ]
          ( -k keyString | -K keyHexString )
          [ inputFile [ ouputFile ] ]

     idea [ -h | -H ] [ -tan | -abr ]
          [ -k keyString | -K keyHexString ]
          [ inputFile [ [ ouputFile ] hashvalFile ]

DESCRIPTION
     Idea reads inputFile and writes  the  en/decrypted  data  to
     outputFile or writes the hash value to hashvalFile.  If file
     name is not given in command line, idea uses standard  input
     or  output.   If  the  input file name is given as '-', idea
     reads from the standard input.

     IDEA (International Data Encryption Algorithm)  is  a  block
     cipher developed by Xuejia Lai and Prof. Dr. J. L. Massey at
     the Swiss Federal Institute of Technology.

OPTIONS
     -e   Encrypt data. (default)

     -d   Decrypt data.

     -r   InputFile is a raster-file.

     -k   Key is specified with keyString.

     -K   Key and initial values are specified with keyHexString.

     -h   Compute a 128 bit hash value from the input  data.  The
          hash  value is written to hashvalFile (or standard out-
          put).

     -H   Compute a 128 bit hash value from the input  data.  The
          input  is copied to outputFile (or standard output) and
          the hash value is written to hashvalFile  (or  standard
          error).

     Notation:
          N           = interleave factor (1 is default)
          z           = 128 bit key
          x[i]        = 64 bit plaintext block
          y[i]        = 64 bit ciphertext block
          x[1]..x[L]  = plaintext  (last  block  is  filled  with
                        zeros)
          x[L+1]      = length of plaintext in bits
          y[1]..y[L+1]= ciphertext
          IDEA(z, .)  = encryption function
          IIDEA(z, .) = decryption function
          x = IIDEA(z, IDEA(z ,x))

     Encryption / Decrypion Modes:

     -ecb electronic code book mode
          y[i] = IDEA(z, x[i])
          x[i] = IIDEA(z, y[i])

     -cbc cipher block chaining mode (cbc1 is default)
          y[i] = IDEA(z, x[i] ^ y[i-N])
          x[i] = IIDEA(z, y[i]) ^ y[i-N]

     -cfb ciphertext feedback mode
          y[i] = x[i] ^ IDEA(z, y[i-N])
          x[i] = y[i] ^ IDEA(z, y[i-N])

     -ofb output feedback mode
          h[i] = IDEA(z, h[i-N])
          y[i] = x[i] ^ h[i]
          x[i] = y[i] ^ h[i]

     Hash Functions:
          If no key is given, idea uses the all zero key.
          hash value = h[L+1] * 2**64 + g[L+1]
          h[0] = z / 2**64
          g[0] = z % 2**64

     -tan tandem DM-scheme (default)
          w = IDEA(g[i-1] * 2**64 + x[i], h[i-1])
          h[i] = h[i-1] ^ w
          g[i] = g[i-1] ^ IDEA(x[i] * 2**64 + w, g[i-1])

     -abr abreast DM-scheme
          h[i] = h[i-1] ^ IDEA(g[i-1] * 2**64 + x[i], h[i-1])
          g[i] = g[i-1] ^ IDEA(x[i] * 2**64 + h[i-1], ~ g[i-1])

     Key Formats:
          keyHexString = { '0'..'9' | 'a'..'f' | 'A'..'F' | ':' }
          keyHexString = z:y[1-N]:y[2-N]:y[3-N]..
          keyString = { '!'..'~' } = z

EXAMPLES
     To encrypt and decrypt a file in cipher block chaining  mode
     with an interleave factor of 8:

          idea -e -cbc8 -K 12345:67:89::ab:cDEf data data.cr
          idea -d -cbc8 -K 12345:67:89::ab:cDef data.cr data.ori
          data and data.ori are identical

     To compute the hash value with tandem DM-scheme:

          idea -h data

     To compute the hash value and encrypt the data in one step:

          idea -Hk "k e y" data | idea -K 123:9a::eF - data.cr

PATENT
     IDEA is registered as the international patent  WO  91/18459
     "Device for Converting a Digital Block and the Use thereof".
     For commercial use of IDEA, one should contact

     ASCOM TECH AG
     Freiburgstrasse 370
     CH-3018 Bern, Switzerland

AUTHOR
     Richard De Moliner (demoliner@isi.ethz.ch)
     Signal and Information Processing Laboratory
     Swiss Federal Institute of Technology
     CH-8092 Zurich, Switzerland

BUGS
     This program is at most as strong as  IDEA  itself.  So,  we
     urge  the user to use this program only after he has assured
     himself that IDEA is strong  enough  AND  he  has  read  the
     source  code  of  this  program and its libraries AND he has
     compiled the program himself with a troyan-free compiler. WE
     DO  NOT  GUARANTEE  THAT THIS PROGRAM IS A DECENT ENCRYPTION
     PROGRAM.

\******************************************************************************/

#ifdef TIME
#include <time.h>
/* #include <sys/times.h> */
#endif
#ifdef RASTER
#include <pixrect/pixrect_hs.h>
#endif

#include <stdio.h>
#include <string.h>
#include "crypt.h"

#define TRUE                 1 /* boolean constant for true                   */
#define FALSE                0 /* boolean constant for false                  */
#define nofTestData     163840 /* number of blocks encrypted in time test     */

#define nomode               0 /* no mode is specified                        */
#define ecb                  1 /* electronic code book mode                   */
#define cbc                  2 /* cipher block chaining mode                  */
#define cfb                  3 /* ciphertext feedback mode                    */
#define ofb                  4 /* output feedback mode                        */
#define tan                  5 /* tandem DM-scheme for hashing                */
#define abr                  6 /* abreast DM-scheme for hashing               */
#define error               -1 /* error constant                              */
#define eol                 -2 /* end of line                                 */
#define colon               -3 /* character ':'                               */
#define maxInterleave     1024 /* maximal interleave factor + 1               */
#define nofChar ('~' - '!' + 1) /* number of different printable characters   */
#define maxBufLen  (dataSize * 1024) /* size of input and output buffer       */

UserKeyT(userKey);             /* user selected 128 bit key                   */
KeyT(key);                     /* expanded key with 832 bits                  */
DataT(state[maxInterleave]);   /* state informations for interleaving modes   */
DataT(hashLow);                /* lower 64 bits of hash value                 */
DataT(hashHigh);               /* higher 64 bits of hash value                */

u_int32 inputLen    = 0;       /* current number of bytes read from 'inFile'  */
int interleave      = 0;       /* current interleave factor                   */
int itime           = 0;       /* time for interleaving modes                 */
int itime_N         = 0;       /* time-interleave for interleaving modes      */
int mode            = nomode;  /* current mode                                */

int optEncrypt      = FALSE;   /* encrypt option 'e'                          */
int optDecrypt      = FALSE;   /* decrypt option 'd'                          */
int optHash         = FALSE;   /* hash option 'h'                             */
int optCopyHash     = FALSE;   /* copy and hash option 'H'                    */
int optKeyHexString = FALSE;   /* key as hex-string option 'K'                */
int optKeyString    = FALSE;   /* key as string option 'k'                    */
#ifdef RASTER
int optRas          = FALSE;   /* raster file option 'r'                      */
#endif
#ifdef TIME
int optTime         = FALSE;   /* measure time option 'T'                     */
#endif

int inBufLen        = maxBufLen; /* current length of data in 'inBuf'         */
int inBufPos        = maxBufLen; /* current read position of 'inBuf'          */
int outBufLen       = 0;       /* current write position of 'outBuf'          */
u_int8 inBuf[maxBufLen];       /* buffer for file read                        */
u_int8 outBuf[maxBufLen];      /* buffer for file write                       */

FILE *inFile;                  /* file with input data (plain or ciphertext)  */
FILE *outFile;                 /* file for output data (plain or ciphertext)  */
FILE *hashFile;                /* 128 bit hash value is written to this file  */

#ifdef RASTER
int pictureSize;               /* stuff related to raster files               */
Pixrect *picPtr;
colormap_t colormap;
u_int8 *picture;
#endif

/******************************************************************************/
/* initialize global variables                                                */

void Init( void )
{
  int i, pos;

  for (i = 0; i < userKeyLen; i++) userKey[i] = 0;
  for (pos = 0; pos < maxInterleave; pos++) {
    for (i = 0; i < dataLen; i++) {
      state[pos][i] = 0;
    }
  }
} /* Init */

/******************************************************************************/
/*                          E R R O R - H A N D L I N G                       */
/******************************************************************************/
/* write usage error message and terminate program                            */

void UsageError( int num )
{
fprintf(stderr, "(%d)\n"
#ifdef RASTER
"Usage:   idea [ -e | -d ] [ -r ] [ -ecb | -cbcN | -cfbN | -ofbN ]\n"
#else
"Usage:   idea [ -e | -d ] [ -ecb | -cbcN | -cfbN | -ofbN ]\n"
#endif
"              ( -k keyString | -K keyHexString )                 \n"
"              [ inputFile [ outputFile ] ]                       \n"
"         idea [ -h | -H ] [ -tan | -abr ]                        \n"
"              [ -k keyString | -K keyHexString ]                 \n"
"              [ inputFile [ [ outputFile ] hashvalFile ] ]       \n"
#ifdef TIME
"         idea -T                                                 \n"
#endif
"\nExample: idea -Hk \"k e y\" infile | idea -cbc8 -K 123:9a::eF - outfile\n"
"\n", num);
  exit(-1);
} /* UsageError */

/******************************************************************************/
/* write error message and terminate program                                  */

void Error( int num, char *str )
{  fprintf(stderr, "error %d in idea: %s\n", num, str); exit(-1); } /* Error */

/******************************************************************************/
/* write system error message and terminate program                           */

void PError( char *str )
{ perror(str); exit(-1); } /* PError */

/******************************************************************************/
/*                          D E C R Y P T I O N  /  E N C R Y P T I O N       */
/******************************************************************************/
/* read one data-block from 'inFile'                                          */

int GetData( DataT(data) )
{
  register int i, len;
  register u_int16 h;
  register u_int8 *inPtr;

  if (inBufPos >= inBufLen) {
    if (inBufLen != maxBufLen) return 0;
    inBufLen = fread(inBuf, 1, maxBufLen, inFile);
    inBufPos = 0;
    if (inBufLen == 0) return 0;
    if (inBufLen % dataSize != 0)
      for (i = inBufLen; i % dataSize != 0; i++) inBuf[i] = 0;
  }
  inPtr = &inBuf[inBufPos];
  for (i = 0; i < dataLen; i++) {
    h = ((u_int16)(*inPtr++) & 0xFF) << 8;
    data[i] = h | ((u_int16)(*inPtr++) & 0xFF);
  }
  inBufPos += dataSize;
  if (inBufPos <= inBufLen) len = dataSize;
  else len = inBufLen + dataSize - inBufPos;
  inputLen += len;
  return len;
} /* GetData */

/******************************************************************************/
/* write one data-block to 'outFile'                                          */

void PutData( DataT(data), int len )
{
  register int i;
  register u_int16 h;
  register u_int8 *outPtr;

  outPtr = &outBuf[outBufLen];
  for (i = 0; i < dataLen; i++) {
    h = data[i];
    *(outPtr++) = (h >> 8) & 0xFF;
    *(outPtr++) = h & 0xFF;
  }
  outBufLen += len;
  if (outBufLen >= maxBufLen) {
    fwrite(outBuf, 1, maxBufLen, outFile);
    outBufLen = 0;
  }
} /* PutData */

/******************************************************************************/
/* write last block to 'outFile' and close 'outFile'                          */

void CloseOutput( void )
{
  if (outBufLen > 0) {
    fwrite(outBuf, 1, outBufLen, outFile);
    outBufLen = 0;
  }
  close(outFile);
} /* CloseOutput */

/******************************************************************************/
/* increment itime and itime_N                                                */

void IncTime( void )
{
  itime = (itime + 1) % maxInterleave;
  itime_N = (itime_N + 1) % maxInterleave;
} /* IncTime */

/******************************************************************************/
/* encrypt one data-block                                                     */

void EncryptData( DataT(data) )
{
  int i;

  switch (mode) {
    case ecb:
      Idea(data, data, key);
      break;
    case cbc:
      for (i = dataLen - 1; i >= 0; i--) data[i] ^= state[itime_N][i];
      Idea(data, data, key);
      for (i = dataLen - 1; i >= 0; i--) state[itime][i] = data[i];
      IncTime();
      break;
    case cfb:
      Idea(state[itime_N], state[itime], key);
      for (i = dataLen - 1; i >= 0; i--) data[i] = state[itime][i] ^= data[i];
      IncTime();
      break;
    case ofb:
      Idea(state[itime_N], state[itime], key);
      for (i = dataLen - 1; i >= 0; i--) data[i] ^= state[itime][i];
      IncTime();
      break;
    default: break;
  }
} /* EncryptData */

/******************************************************************************/
/* decrypt one data-block                                                     */

void DecryptData( DataT(data) )
{
  int i;

  switch (mode) {
    case ecb:
      Idea(data, data, key);
      break;
    case cbc:
      for (i = dataLen - 1; i >= 0; i--) state[itime][i] = data[i];
      Idea(data, data, key);
      for (i = dataLen - 1; i >= 0; i--) data[i] ^= state[itime_N][i];
      IncTime();
      break;
    case cfb:
      for (i = dataLen - 1; i >= 0; i--) state[itime][i] = data[i];
      Idea(state[itime_N], data, key);
      for (i = dataLen - 1; i >= 0; i--) data[i] ^= state[itime][i];
      IncTime();
      break;
    case ofb:
      Idea(state[itime_N], state[itime], key);
      for (i = dataLen - 1; i >= 0; i--) data[i] ^= state[itime][i];
      IncTime();
      break;
    default: break;
  }
} /* DecryptData */

/******************************************************************************/
/* hash one data-block                                                        */

void HashData( DataT(data) )
{
  int i;
  UserKeyT(userKey);
  KeyT(key);
  DataT(w);

  for (i = dataLen - 1; i >= 0; i--) { 
    userKey[i] = hashLow[i];
    userKey[i + dataLen] = data[i]; 
  }
  ExpandUserKey(userKey, key);
  Idea(hashHigh, w, key);
  if (mode == abr) {
    for (i = dataLen - 1; i >= 0; i--) { 
      userKey[i] = data[i];
      userKey[i + dataLen] = hashHigh[i]; 
      hashHigh[i] ^= w[i];
      w[i] = ~ hashLow[i];
    }
  }
  else { /* mode == tan */
    for (i = dataLen - 1; i >= 0; i--) {
      hashHigh[i] ^= w[i];
      userKey[i] = data[i];
      userKey[i + dataLen] = w[i];
      w[i] = hashLow[i];
    }
  }
  ExpandUserKey(userKey, key);
  Idea(w, w, key);
  for (i = dataLen - 1; i >= 0; i--) hashLow[i] ^= w[i];
} /* HashData */

/******************************************************************************/
/* write value of a 16-bit unsigned integer in hex format to 'hashFile'       */

void WriteHex( u_int16 val )
{
  char str[8];
  int i;

  sprintf(str, "%4X", val);
  for (i = 0; i < 4; i++) if (str[i] == ' ') str[i] = '0';
  fprintf(hashFile, "%s", str);
} /* WriteHex */

/******************************************************************************/
/* write the hash value to 'hashFile'                                         */

void WriteHashValue( void )
{
  int i;

  for (i = 0; i < dataLen; i++) WriteHex(hashHigh[i]);
  for (i = 0; i < dataLen; i++) WriteHex(hashLow[i]);
} /* WriteHashValue */

/******************************************************************************/
/* store integer 'value' in 'data'                                            */

void PlainLenToData( u_int32 value, DataT(data) )
{
  data[3] = (u_int16)((value << 3) & 0xFFFF);
  data[2] = (u_int16)((value >> 13) & 0xFFFF);
  data[1] = (u_int16)((value >> 29) & 0x0007);
  data[0] = 0;
} /* PlainLenToData */

/******************************************************************************/
/* extract integer 'value' from 'data'                                        */

void DataToPlainLen( DataT(data), u_int32 *value )
{
  if ((data[0] != 0) || (data[1] > 7) || ((data[3] & 7) != 0))
    Error(1, "input is not a valid cryptogram");
  *value = ((u_int32)(data[3]) >> 3) & 0x1FFF |
           ((u_int32)(data[2]) << 13) |
           ((u_int32)(data[1]) << 29);
} /* DataToPlainLen */

/******************************************************************************/
/* encrypt / decrypt complete data-stream or compute hash value of data-stream*/

void CryptData( void )
{
  int t, i;
  u_int32 len;
  DataT(dat[4]);
  DataT(data);

#ifdef RASTER
  if (optRas) {
    if (optEncrypt)
      for (i = 0; i <= (pictureSize - dataSize); i += dataSize)
        EncryptData((u_int16 *)&picture[i]);
    else
      for (i = 0; i <= (pictureSize - dataSize); i += dataSize)
        DecryptData((u_int16 *)&picture[i]);
  } else
#endif
  if (optEncrypt) { /* encrypt data */
    while ((len = GetData(data)) == dataSize) {
      EncryptData(data); 
      PutData(data, dataSize); 
    }
    if (len > 0) { EncryptData(data); PutData(data, dataSize); }
    PlainLenToData(inputLen, data);
    EncryptData(data);
    PutData(data, dataSize);
    CloseOutput();
  }
  else if (optDecrypt) { /* decrypt data */
    if ((len = GetData(dat[0])) != dataSize) {
      if (len != 0) Error(2, "input is not a valid cryptogram");
      else Error(3, "there are no data to decrypt");
    }
    DecryptData(dat[0]);
    if ((len = GetData(dat[1])) != dataSize) {
      if (len != 0) Error(4, "input is not a valid cryptogram");
      DataToPlainLen(dat[0], &len);
      if (len != 0) Error(5, "input is not a valid cryptogram");
    }
    else {
      DecryptData(dat[1]);
      t = 2;
      while ((len = GetData(dat[t])) == dataSize) {
        DecryptData(dat[t]);
        PutData(dat[(t + 2) & 3], dataSize);
        t = (t + 1) & 3;
      }
      if (len != 0) Error(6, "input is not a valid cryptogram");
      DataToPlainLen(dat[(t + 3) & 3], &len);
      len += 2 * dataSize;
      if ((inputLen < len) && (len <= inputLen + dataSize)) {
        len -= inputLen;
        PutData(dat[(t + 2) & 3], len);
      }
      else Error(7, "input is not a valid cryptogram");
    }
    CloseOutput();
  }
  else { /* compute hash value */
    for (i = dataLen - 1; i >= 0; i--) {
      hashHigh[i] = userKey[i];
      hashLow[i] = userKey[i + dataLen];
    }
    if (optCopyHash) { 
      while ((len = GetData(data)) == dataSize) {
        HashData(data); 
        PutData(data, dataSize); 
      }
      if (len > 0) { HashData(data); PutData(data, len); }
      PlainLenToData(inputLen, data);
      HashData(data);
      CloseOutput();
    }
    else { /* optHash */
      while ((len = GetData(data)) == dataSize) HashData(data); 
      if (len > 0) HashData(data);
      PlainLenToData(inputLen, data);
      HashData(data);
    }
    WriteHashValue();
  }
} /* CryptData */

/******************************************************************************/
/* measure the time to encrypt 'nofTestData' data-blocks                      */

#ifdef TIME
void TimeTest( void )
{ 
  clock_t startTime, endTime;
  DataT(data);
  int i;
  unsigned long size, time;

  for (i = 0; i < dataLen; i++)
	data[i] = 0;
  ExpandUserKey(userKey, key);
  if(optDecrypt)
	InvertIdeaKey(key, key);
  startTime = clock();
  if (startTime == 0) PError("(8) clock");
  for (i = 0; i < nofTestData; i++) Idea(data, data, key);
  endTime = clock();
  if (endTime == 0) PError("(9) clock");
  size = nofTestData * dataSize * 8;
  time = (endTime-startTime)*1000 / CLOCKS_PER_SEC;
  fprintf(stderr, "Time needed to encrypt %lu bits of data (%lu.%1lu Mbit)\n"
	"was %lu.%03lu seconds, %lu bits/second = %lu.%01lu kbit/sec)\n",
	size, size>>20, ((size*5)>>19)%10, time/1000, time%1000,
	size*100/(time/10),  size/128*125/time, (size/64*625/time)%10);
} /* TimeTest */
#endif

/******************************************************************************/
/*                          I N I T I A L I Z A T I O N                       */
/******************************************************************************/
/* set option to TRUE                                                         */

void SetOption( int *option )
{
  if (*option) UsageError(10);
  *option = TRUE;
} /* SetOption */

/******************************************************************************/
/* set encryption / decryption mode                                           */

void SetMode( int newMode, char **str )
{
  if (mode != nomode) UsageError(11);
  mode = newMode;
  (*str)++; (*str)++;
  if ((newMode == cbc) || (newMode == cfb) || (newMode == ofb)) {
    if (('0' <= **str) && (**str <= '9')) {
      interleave = 0;
      do {
        interleave = 10 * interleave + (**str - '0');
        if (interleave >= maxInterleave)
          Error(12, "interleave factor is too large");
        (*str)++;
      } while (('0' <= **str) && (**str <= '9'));
      if (interleave == 0) Error(13, "interleave factor is zero");
    }
    else interleave = 1;
  }
} /* SetMode */

/******************************************************************************/
/* read options from string 'str'                                             */

void ReadOptions( char *str, int *readKeyString, int *readKeyHexString)
{
  char ch;

  str++;
  *readKeyString = *readKeyHexString = FALSE;
  while((ch = *(str++)) != 0) {
    switch (ch) {
      case 'a':
        if ((str[0] == 'b') && (str[1] == 'r')) SetMode(abr, &str);
        else UsageError(14);
        break;
      case 'c':
        if ((str[0] == 'b') && (str[1] == 'c')) SetMode(cbc, &str);
        else if ((str[0] == 'f') && (str[1] == 'b')) SetMode(cfb, &str);
        else UsageError(15);
        break;
      case 'd': SetOption(&optDecrypt); break;
      case 'e': 
        if ((str[0] == 'c') && (str[1] == 'b')) SetMode(ecb, &str);
        else SetOption(&optEncrypt);
        break;
      case 'h': SetOption(&optHash); break;
      case 'H': SetOption(&optCopyHash); break;
      case 'o':
        if ((str[0] == 'f') && (str[1] == 'b')) SetMode(ofb, &str);
        else UsageError(16);
        break;
      case 'k': SetOption(&optKeyString); *readKeyString = TRUE; break;
      case 'K': SetOption(&optKeyHexString); *readKeyHexString = TRUE; break;
      case 't':
        if ((str[0] == 'a') && (str[1] == 'n')) SetMode(tan, &str);
        else UsageError(17);
        break;
#ifdef RASTER
      case 'r': SetOption(&optRas); break;
#endif
#ifdef TIME
      case 'T': SetOption(&optTime); break;
#endif
      default: UsageError(18); break;
    }
  }
  if (*readKeyString && *readKeyHexString) UsageError(19);
} /* ReadOptions */

/******************************************************************************/
/* check if options are unique and set default options                        */

void AdjustOptions( void )
{
#ifdef TIME
  if (optTime && (optHash || optCopyHash || mode != nomode
#ifdef RASTER
	 || optRas
#endif
		)) UsageError(20);
#endif
  if (optDecrypt && optEncrypt) UsageError(21);
  if (optHash && optCopyHash) UsageError(22);
  if (optKeyString && optKeyHexString) UsageError(23);
  if (optDecrypt || optEncrypt) {
    if (optHash || optCopyHash) UsageError(24);
    if ((! optKeyString) && (! optKeyHexString)) UsageError(25);
    if (mode == nomode) { mode = cbc; interleave = 1; }
    else if ((mode == tan) || (mode == abr)) UsageError(26);
  }
  else {
    if (optHash || optCopyHash) {
      if (mode == nomode) mode = tan;
      else if ((mode != tan) && (mode != abr)) UsageError(27);
    }
    else {
      if (mode == nomode) { mode = cbc; interleave = 1; }
      if ((mode == tan) || (mode == abr)) SetOption(&optHash);
      else SetOption(&optEncrypt);
    }
  }
#ifdef RASTER
  if (optRas && (optHash || optCopyHash)) UsageError(28);
#endif
  itime = interleave;
  itime_N = 0;
} /* AdjustOptions */

/******************************************************************************/
/* convert a hex-digit into an integer                                        */

int HexToInt( char ch )
{
  if (('0' <= ch) && (ch <= '9')) return ch - '0';
  else if (('a' <= ch)  && (ch <= 'f')) return 10 + (ch - 'a');
  else if (('A' <= ch) && (ch <= 'F')) return 10 + (ch - 'A');
  else if (ch == ':') return colon;
  else if (ch == 0) return eol;
  else return error;
} /* HexToInt */

/******************************************************************************/
/* convert a character into an integer                                        */

int32 CharToInt( char ch )
{
  if (('!' <= ch) && (ch <= '~')) return ch - '!';
  else if (ch == 0) return eol;
  else return error;
} /* CharToInt */

/******************************************************************************/
/* initializes key and initial values                                         */

void ReadKeyHexString( char *str )
{
  int i, pos;
  int32 h, val;

  while ((val = HexToInt(*(str++))) >= 0) {
    for (i = userKeyLen - 1; i >= 0; i--) {
      h = ((int32)(userKey[i]) >> 12) & 0xF;
      userKey[i] = ((int32)(userKey[i]) << 4) | val;
      val = h;
    }
    if (val != 0) Error(29, "key value is too large");
  }
  pos = 0;
  while ((val == colon) && (pos < maxInterleave)) {
    val = HexToInt(*(str++));
    while (val >= 0) {
      for (i = dataLen - 1; i >= 0; i--) {
        h = ((int32)(state[pos][i]) >> 12) & 0xF;
        state[pos][i] = ((int32)(state[pos][i]) << 4) | val;
        val = h;
      }
      if (val != 0) Error(30, "initial value is too large");
      val = HexToInt(*(str++));
    }
    pos++;
  }
  if (val == colon) Error(31, "too many initial values specified");
  if (val != eol) Error(32, "wrong character in initialization string");
} /* ReadKeyHexString */

/******************************************************************************/
/* initialize key and initial values                                          */

void ReadKeyString( char *str )
{
  int i;
  int32 h, val;

  while ((val = CharToInt(*(str++))) >= 0) {
    for (i = userKeyLen - 1; i >= 0; i--) {
      h = (int32)(userKey[i]) * nofChar + val;
      userKey[i] = h & 0xFFFF;
      val = h >> 16;
    }
  }
} /* ReadKeyString */

/******************************************************************************/
/* show value of a 16-bit unsigned integer in decimal and hex format          */

void ShowInt16( u_int16 val )
{
  fprintf(stderr, "%7u<%4x>", val, val);
} /* ShowInt16 */

/******************************************************************************/
/* show option name if option is set                                          */

void ShowOption( int option, char *name )
{
  if (option) fprintf(stderr, ", %s", name);
} /* ShowOption */


/******************************************************************************/
/* show current state informations                                            */

void ShowState()
{
  int i, j;

  fprintf(stderr, "Mode = {");
  switch (mode) {
    case ecb: fprintf(stderr, "ecb"); break;
    case cbc: fprintf(stderr, "cbc"); break;
    case cfb: fprintf(stderr, "cfb"); break;
    case ofb: fprintf(stderr, "ofb"); break;
    case tan: fprintf(stderr, "tan"); break;
    case abr: fprintf(stderr, "abr"); break;
    case nomode: fprintf(stderr, "nomode"); break;
    default: fprintf(stderr, "!!!wrong mode!!!"); break;
  }
  if (interleave > 0) fprintf(stderr, "%d", interleave);
  ShowOption(optEncrypt, "encrypt");
  ShowOption(optDecrypt, "decrypt");
  ShowOption(optHash, "hash");
  ShowOption(optCopyHash, "copy and hash");
  ShowOption(optKeyString, "key string");
  ShowOption(optKeyHexString, "key hex string");
#ifdef RASTER
  ShowOption(optRas, "raster file");
#endif
#ifdef TIME
  ShowOption(optTime, "time test");
#endif
  fprintf(stderr, "}\n\nKey:\n");
  for (i = 0; i < keyLen; i++) {
    ShowInt16(key[i]);
    if ((i % 6) == 5) fprintf(stderr, "\n");
  }
  fprintf(stderr, "\n\nInitial values:");
  for (i = 0; i < interleave; i++) {
    fprintf(stderr, "\n  x[N -%2d] =", i + 1);
    for (j = 0; j < dataLen; j++) ShowInt16(state[i][j]);
  }
  fprintf(stderr, "\n");
} /* ShowState */

/******************************************************************************/
/* read picture from 'inFile' to memory                                       */

#ifdef RASTER
void ReadRasFile( void )
{
  if ((picPtr = pr_load(inFile, &colormap)) == NULL)
    PError("(33) input is not a rasterfile");
  if (picPtr->pr_depth != 8) Error(34, "depth of rasterfile should bee 8");
  picture = (u_int8 *)mpr_d(picPtr)->md_image;
  pictureSize = picPtr->pr_height * picPtr->pr_width;
} /* ReadRasFile */
#endif

/******************************************************************************/
/* write picture from memory to 'outFile'                                     */

#ifdef RASTER
void WriteRasFile( void )
{
  if (pr_dump(picPtr, outFile, &colormap, RT_STANDARD, FALSE) != NULL)
    PError("(34) writing rasterfile");
} /* WriteRasFile */
#endif

/******************************************************************************/
/*                          M A I N - P R O C E D U R E                       */
/******************************************************************************/
main( int argc, char *argv[] )
{
  int readKeyString, readKeyHexString;

  Init();
  argv++; argc--;
  while ((argc > 0) && (*(argv[0]) == '-') && (*(argv[0]+1) != '\0')) {
    ReadOptions(*argv++, &readKeyString, &readKeyHexString); argc--;
    if (readKeyString || readKeyHexString) {
      if (argc <= 0)  Error(36, "missing key on command line");
      else if (readKeyString) { ReadKeyString(*(argv++)); argc--; }
      else { ReadKeyHexString(*(argv++)); argc--; }
    }
  }
  AdjustOptions();
  if ((optTime && (argc > 0)) || (optCopyHash && (argc > 3)) || 
      (! optCopyHash && (argc > 2))) Error(37, "too many parameters");
  ExpandUserKey(userKey, key);
  if (optDecrypt && ((mode == ecb) || (mode == cbc))) InvertIdeaKey(key, key);
#ifdef TIME
  if (optTime) TimeTest();
#endif
  else {
    if ((argc > 1) && (strcmp(argv[0], argv[1]) == 0))
      Error(38, "source and destination are identical");
    if ((argc > 2) && (strcmp(argv[0], argv[2]) == 0))
      Error(39, "source and destination are identical");
    if ((argc > 2) && (strcmp(argv[1], argv[2]) == 0))
      Error(40, "destinations are identical");
    inFile = stdin;
    outFile = hashFile = stdout;
    if (argc > 0) {
      if (strcmp(*argv, "-") == 0) { argv++; argc--; }
      else {
        inFile = fopen(*argv++, "r"); argc--;
        if (inFile == 0) PError(*--argv);
      }
    }
    if (optCopyHash) {
      if (argc > 1) {
        outFile = fopen(*argv++, "w"); argc--;
        if (outFile == 0) PError(*--argv);
      }
      if (argc > 0) {
        hashFile = fopen(*argv++, "w"); argc--;
        if (hashFile == 0) PError(*--argv);
      }
      else hashFile = stderr;
    }
    else if (optHash) {
      if (argc > 0) {
        hashFile = fopen(*argv++, "w"); argc--;
        if (hashFile == 0) PError(*--argv);
      }
    }
    else {
      if (argc > 0) {
        outFile = fopen(*argv++, "w"); argc--;
        if (outFile == 0) PError(*--argv);
      }
    }
    if (argc > 0) Error(41, "too many parameters");
/*  ShowState(); */
#ifdef RASTER
    if (optRas) ReadRasFile();
#endif
    CryptData();
#ifdef RASTER
    if (optRas) WriteRasFile();
#endif
  }
  exit(0);
}
