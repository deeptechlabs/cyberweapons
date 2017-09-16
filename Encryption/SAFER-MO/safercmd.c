/*******************************************************************************
*
* FILE:           safercmd.c
*
* DESCRIPTION:    block-cipher algorithm SAFER (Secure And Fast Encryption
*                 Routine) in its four versions: SAFER K-64, SAFER K-128,
*                 SAFER SK-64 and SAFER SK-128 as a user-command
*
* AUTHOR:         Richard De Moliner (demoliner@isi.ee.ethz.ch)
*                 Signal and Information Processing Laboratory
*                 Swiss Federal Institute of Technology
*                 CH-8092 Zuerich, Switzerland
*
* DATE:           September 9, 1995
*
* CHANGE HISTORY:
*
*******************************************************************************/

/******************* External Headers *****************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef TIME
#include <time.h>
#endif

/******************* Local Headers ********************************************/
#include "safer.h"

/******************* Constants ************************************************/
#ifndef TRUE
#define TRUE                  1 /* boolean constant for true                  */
#endif
#ifndef FALSE
#define FALSE                 0 /* boolean constant for false                 */
#endif

#define NOF_CHARS          ('~' - ' ' + 1) /* number of printable characters  */
#define END_OF_LINE        (NOF_CHARS + 0) /* end of line character           */
#define COLON              (NOF_CHARS + 1) /* character ':'                   */
#define ILLEGAL_CHAR       (NOF_CHARS + 2) /* illegal character               */
#define MAX_BUF_LEN (SAFER_BLOCK_LEN*1024) /* size of input and output buffers*/
#define MAX_SHORT_KEY_STRING_LEN        9  /* maximal length for a 64-bit key */

                                /* options: */
#define WRITE_HELP            0 /* write help text to standard output         */
#define ECB                   1 /* electronic code book mode (encryption)     */
#define CBC                   2 /* cipher block chaining mode (encryption)    */
#define CFB                   3 /* ciphertext feedback mode (encryption)      */
#define OFB                   4 /* output feedback mode (encryption)          */
#define TAN                   5 /* tandem mode (hash)                         */
#define ABR                   6 /* abreast mode (hash)                        */
#define ENCRYPT               7 /* encrypt input                              */
#define DECRYPT               8 /* decrypt input                              */
#define COPY_AND_HASH         9 /* copy input and compute hash value          */
#define HASH                 10 /* compute hash value                         */
#define KEY_HEX_STRING       11 /* key is given as hexadecimal values         */
#define KEY_STRING           12 /* key is given as a string                   */
#define ROUNDS               13 /* number of rounds in encryption algorithm   */
#define STRENGTHENED         14 /* use strengthened key schedule              */
#define MEASURE              15 /* measure encryption speed                   */
#define VERBOSE              16 /* write state information to standard error  */
#define NOF_OPTIONS          17

/******************* Assertions ***********************************************/

/******************* Macros ***************************************************/

/******************* Types ****************************************************/

/******************* Prototypes ***********************************************/
#ifndef NOT_ANSI_C
    static void Read_Key_String(char *str);
    static void Read_Key_Hex_String(char *str);
    static void Read_Rounds(char *str);
#else
    static Read_Key_String();
    static Read_Key_Hex_String();
    static Read_Rounds();
#endif

/******************* Module Data **********************************************/
static struct option_t
{
    char text[5];
    int set;
#ifndef NOT_ANSI_C
    void (*read_func)(char *);
#else
    int (*read_func)();
#endif
}
option[NOF_OPTIONS] =
{
    { "help", FALSE, NULL },
    { "ecb",  FALSE, NULL },
    { "cbc",  FALSE, NULL },
    { "cfb",  FALSE, NULL },
    { "ofb",  FALSE, NULL },
    { "tan",  FALSE, NULL },
    { "abr",  FALSE, NULL },
    { "e",    FALSE, NULL },
    { "d",    FALSE, NULL },
    { "hc",   FALSE, NULL },
    { "h",    FALSE, NULL },
    { "kx",   FALSE, Read_Key_Hex_String },
    { "k",    FALSE, Read_Key_String },
    { "r",    FALSE, Read_Rounds },
    { "s",    FALSE, NULL },
    { "m",    FALSE, NULL },
    { "v",    FALSE, NULL }
};

#define NOF_TEXTS           21

static char text[NOF_TEXTS][80] = 
{
/*  0 */ "could not open input file",
/*  1 */ "could not create output file",
/*  2 */ "could not start timer",
/*  3 */ "could not stop timer",
/*  4 */ "illegal character in",
/*  5 */ "key is too large",
/*  6 */ "initial value is too large",
/*  7 */ "number of rounds is too large (> 13)",
/*  8 */ "only one initial value can be specified",
/*  9 */ "too many arguments",
/* 10 */ "source and destination are identical",
/* 11 */ "destinations are identical",
/* 12 */ "there is no data to decrypt",
/* 13 */ "input is not a valid cryptogram or key is wrong",
/* 14 */ "for hashing no ':' is allowed in 'keyHexString'",
/* 15 */ "for ecb-mode no ':' is allowed in 'keyHexString'",
/* 16 */ "safer: enter key string (up to 8 characters): ",
/* 17 */ "safer: repeat key string                    : ",
/* 18 */ "key strings are not identical",
/* 19 */ "illegal key string",
/* 20 */ "could not write to output file"
};

static safer_block_t userkey_1; /* first 64 bits of user-selected key         */
static safer_block_t userkey_2; /* second 64 bits of user-selected key        */
static safer_key_t key;         /* expanded key                               */
static safer_block_t last_block;/* used for CBC, CFB and OFB modes            */

static int userkey_2_set;       /* 'userkey_2' has been set                   */
static int last_block_set;      /* 'last_block' has been set                  */
static unsigned int nof_rounds; /* number of rounds in encryption algorithm   */
static int mode;                /* encryption/decryption or hash mode         */

static unsigned long int input_len; /* number of bytes read from 'in_file'    */
static unsigned int in_buf_len;     /* length of data in 'in_buf'             */
static unsigned int in_buf_pos;     /* read position of 'in_buf'              */
static unsigned int out_buf_len;    /* write position of 'out_buf'            */
static unsigned char in_buf[MAX_BUF_LEN];  /* buffer for file read            */
static unsigned char out_buf[MAX_BUF_LEN]; /* buffer for file write           */

static FILE *in_file;           /* file with input data (plain or ciphertext) */
static FILE *out_file;          /* file for output data (plain or ciphertext) */
static FILE *hash_file;         /* 128-bit hash value is written to this file */

/******************* Functions ************************************************/

/*******************************************************************************
* initialize global variables
*/
#ifndef NOT_ANSI_C
    static void Init_Module(void)
#else
    static Init_Module()
#endif

{   int i;

    Safer_Init_Module();
    for (i = 0; i < SAFER_BLOCK_LEN; i++)
        userkey_1[i] = userkey_2[i] = last_block[i] = 0;
    userkey_2_set = last_block_set = FALSE;
    input_len = 0;
    in_buf_len = MAX_BUF_LEN;
    in_buf_pos = MAX_BUF_LEN;
    out_buf_len = 0;
} /* Init_Module */

/*******************************************************************************
* clear global key and data
*/
#ifndef NOT_ANSI_C
    static void Free_Module(void)
#else
    static Free_Module()
#endif

{   int i;

    for (i = 0; i < SAFER_BLOCK_LEN; i++)
        userkey_1[i] = userkey_2[i] = last_block[i] = 0;
    for (i = 0; i < SAFER_KEY_LEN; i++)
        key[i] = 0;
    for (i = 0; i < MAX_BUF_LEN; i++)
        in_buf[i] = out_buf[i] = 0;
} /* Free_Module */

/*******************************************************************************
*                         E R R O R - H A N D L I N G
*******************************************************************************/

/*******************************************************************************
* write usage error message and terminate program
*/
#ifndef NOT_ANSI_C
    static void Usage_Error(void)
#else
    static Usage_Error()
#endif

{   fprintf(stderr, "\
Usage:   safer [ -e | -d ] [ -ecb | -cbc | -cfb | -ofb ]\n\
               %c -k keyString | -kx keyHexString %c\n\
               [ -r nofRounds ] [ -s ] [ -v ]\n\
               [ inputFile [ outputFile ] ]\n\
         safer [ -h | -hc ] [ -tan | -abr ]\n\
               [ -k keyString | -kx keyHexString ]\n\
               [ -r nofRounds ] [ -s ] [ -v ]\n\
               [ inputFile [ [ outputFile ] hashvalFile ] ]\n",
#ifdef GETPASS
    '[', ']');
#else
    '(', ')');
#endif
#ifdef TIME
    fprintf(stderr, "         safer -m -r nofRounds\n");
#endif
#ifdef HELP
    fprintf(stderr, "         safer -help\n");
#endif
    fprintf(stderr, "\n\
Example: safer -hcsk \"k e y\" infile | safer -ofb -s -kx 123:9a - outfile\n");
    Free_Module();
    exit(-1);
} /* Usage_Error */

/*******************************************************************************
* write error message and terminate program
*/
#ifndef NOT_ANSI_C
    static void Error(int num, char *str)
#else
    static Error(num, str)
    int num;
    char *str;
#endif

{   fprintf(stderr, "Error in safer:");
    if (0 <= num && num < NOF_TEXTS)
        fprintf(stderr, " %s", text[num]);
    if (str != NULL)
        fprintf(stderr, " \"%s\"", str);
    fprintf(stderr, "\n");
    Free_Module();
    exit(1);
} /* Error */

/*******************************************************************************
* write help text to standard output
*/

#ifndef NOT_ANSI_C
    static void Write_Help_Text(void)
#else
    static Write_Help_Text()
#endif

{
#ifdef HELP
    printf("\
NAME\n\
     safer - encryption and decryption using SAFER\n\
\n\
SYNOPSIS\n\
     safer\n\
          [ -e | -d ] [ -ecb | -cbc | -cfb | -ofb ]\n\
          ( -k keyString | -kx keyHexString )\n\
          [ -r nofRounds ] [ -s ] [ -v ]\n\
          [ inputFile [ outputFile ] ]\n\
\n\
     safer\n\
          [ -h | -hc ] [ -tan | -abr ]\n\
          [ -k keyString | -kx keyHexString ]\n\
          [ -r nofRounds ] [ -s ] [ -v ]\n\
          [ inputFile [ [ outputFile ] hashvalFile ]\n\
\n\
DESCRIPTION\n\
     Safer reads inputFile and writes the encrypted or  decrypted\n\
     data  to outputFile or writes the hash value to hashvalFile.\n\
     If a file name is not given in command line, safer uses  the\n\
     standard  input  or output.  If the input file name is given\n\
     as '-', safer reads from the standard input.\n\
 \n\
     SAFER [1] (Secure And Fast Encryption Routine)  is  a  block\n\
     cipher  developed  by Prof. J.L. Massey at the Swiss Federal\n\
     Institute of Technology.  There exist four versions of  this\n\
     algorithm,  namely:  SAFER  K-64 [1], SAFER K-128 [2], SAFER\n\
     SK-64 [3] and SAFER SK-128 [3].  The  numerals  64  and  128\n\
     stand  for  the  length of the user-selected key, 'K' stands\n\
     for the original  key  schedule  and  'SK'  stands  for  the\n\
     strengthened key schedule (in which some of the \"weaknesses\"\n\
     of the original key schedule have been removed).\n\
\n\
OPTIONS\n\
     -e   Encryption (default).\n\
\n\
     -d   Decryption.\n\
\n\
     -k   The key is  specified with keyString.  If the length of\n\
          keyString  is  less  than  10  characters, keyString is\n\
          interpreted as a 64-bit key,  otherwise  as  a  128-bit\n\
          key.\n"); printf("\
\n\
     -kx  The key is  specified with keyHexString.  If the length\n\
          of  keyHexString  is  less  than 17 hex digits, keyHex-\n\
          String is interpreted as a 64-bit key, otherwise  as  a\n\
          128-bit  key.  For the modes -cbc, -cfb and -ofb, it is\n\
          possible to specify an initial value denoted  by  y[0].\n\
          In  this  case  the  key  and  the  initial  value  are\n\
          separated by a colon, e.g. '1234:9A'.\n\
\n\
     -r   nofRounds gives the number of rounds  in the encryption\n\
          (resp.  decryption)  process.   Default  values  are  6\n\
          rounds for SAFER K-64, 8 rounds for SAFER SK-64 and  10\n\
          rounds for SAFER K-128 and SAFER SK-128.\n\
\n\
     -s   The strengthened key schedule contained in SAFER  SK-64\n\
          or  SAFER  SK-128  is used, instead of the original key\n\
          schedule contained in SAFER K-64 or SAFER K-128.\n\
\n\
     -h   Compute a 128-bit hash  value from the input data.  The\n\
          hash  value is written to hashvalFile (or standard out-\n\
          put).\n\
\n\
     -hc  Compute a 128-bit hash  value from the input data.  The\n\
          input  is copied to outputFile (or standard output) and\n\
          the hash value is written to hashvalFile  (or  standard\n\
          error).\n\
\n\
     -v   Verbose mode.  The selected parameters are  written  to\n\
          standard error.\n\
\n\
     Notation:\n"); printf("\
          z            = 64-bit or 128-bit key\n\
          x[i]         = i-th 64-bit plaintext block (i = 1..L+1)\n\
          y[i]         = i-th  64-bit  ciphertext  block   (i   =\n\
                         1..L+1)\n\
          x[1]..x[L]   = actual plaintext (last block  is  filled\n\
                         with zeros)\n\
          x[L+1]       = length of actual plaintext in bits\n\
          x[1]..x[L+1] = plaintext\n\
          y[1]..y[L+1] = ciphertext\n\
          <a, b>       = 128-bit block  composed  of  two  64-bit\n\
                         blocks\n\
          E(z, .)      = encryption function under the key z\n\
          D(z, .)      = decryption function, x = D(z, E(z, x))\n\
          ^            = bit-by-bit exclisive-OR\n\
          ~            = bit-by-bit complement\n\
\n\
     Encryption / Decryption Modes:\n\
\n\
     -ecb electronic code book mode\n\
          y[i] = E(z, x[i])\n\
          x[i] = D(z, y[i])\n\
\n\
     -cbc cipher block chaining mode (default)\n\
          y[i] = E(z, x[i] ^ y[i-1])\n\
          x[i] = D(z, y[i]) ^ y[i-1]\n\
\n\
     -cfb ciphertext feedback mode\n\
          y[i] = x[i] ^ E(z, y[i-1])\n\
          x[i] = y[i] ^ E(z, y[i-1])\n\
\n\
     -ofb output feedback mode\n\
          h[i] = E(z, h[i-1])\n\
          y[i] = x[i] ^ h[i]\n\
          x[i] = y[i] ^ h[i]\n\
\n\
     Hash Functions:\n\
          If no key is given, safer uses the all zero key.\n\
          <h[0], g[0]> = z\n\
          hash value = <h[L+1], g[L+1]>\n\
\n\
     -tan tandem Davies-Meyer scheme (default)\n\
          w[i] = E(<g[i-1], x[i]>, h[i-1])\n\
          h[i] = h[i-1] ^ w[i]\n\
          g[i] = g[i-1] ^ E(<x[i], w[i]>, g[i-1])\n\
\n\
     -abr abreast Davies-Meyer scheme\n\
          h[i] = h[i-1] ^ E(<g[i-1], x[i]>, h[i-1])\n\
          g[i] = g[i-1] ^ E(<x[i], h[i-1]>, ~g[i-1])\n\
\n\
     Key Formats:\n\
          keyHexString  =  z:y[0]  =  {  '0'..'9'  |  'a'..'f'  |\n\
          'A'..'F' | ':' }\n\
          keyString = z = { ' '..'~' }\n\
\n\
EXAMPLES\n"); printf("\
     To encrypt and decrypt a file in ciphertext feedback mode:\n\
\n\
          safer -e -cfb -kx 123456:cDd7 data data.cr\n\
          safer -d -cfb -kx 123456:cDd7 data.cr data.ori\n\
          data and data.ori are identical\n\
\n\
     To compute the hash value:\n\
\n\
          safer -h data\n\
\n\
     To compute the hash value and encrypt the data in one step:\n\
\n\
          safer -hck \"k e y\" data | safer -kx 12E3 - data.cr\n\
\n\
PATENT\n\
     \"Although our design of SAFER K-64 was sponsored  by  Cylink\n\
     Corporation  (Sunnyvale,  CA,  USA),  Cylink  has explicitly\n\
     relinquished any proprietary rights to this algorithm.  This\n\
     largesse  on the part of Cylink was motivated by the reason-\n\
     ing that the company would gain more from new business  than\n\
     it  would  lose from competition should many new users adopt\n\
     this publicly available cipher.  SAFER  K-64  has  not  been\n\
     patented  and, to the best of our knowledge, is free for use\n\
     by anyone without fees of any kind and with no violation  of\n\
     any rights of ownership, intellectual or otherwise.\" [2]\n\
\n\
REFERENCES\n\
     [1]  Massey,  J.L.,  \"SAFER  K-64:  A  Byte-Oriented   Block\n\
          Ciphering Algorithm\", pp. 1-17 in Fast Software Encryp-\n\
          tion (Ed. R. Anderson), Proceedings  of  the  Cambridge\n\
          Security  Workshop,  Cambridge,  U.K., Dec. 9-11, 1993,\n\
          Lecture Notes in Computer Science No. 809.   Heidelberg\n\
          and New York: Springer, 1994.\n\
\n\
     [2]  Massey, J.L., \"SAFER K-64: One Year Later\", preliminary\n\
          manuscript  of  a  paper  presented at the K. U. Leuven\n\
          Workshop on Cryptographic Algorithms, Dec. 14-16, 1994.\n\
          To  be published in the Proceedings of this workshop by\n\
          Springer.\n\
\n\
     [3]  Massey,  J.L.,  \"Announcement  of  a  Strengthened  Key\n\
          Schedule  for  the  Cipher  SAFER\", Sept. 9, 1995, (see\n\
          file 'SAFER_SK.TXT' on distribution).\n\
\n\
AUTHOR\n"); printf("\
     Richard De Moliner (demoliner@isi.ee.ethz.ch)\n\
     Signal and Information Processing Laboratory\n\
     Swiss Federal Institute of Technology\n\
     CH-8092 Zurich, Switzerland\n\
\n\
BUGS\n\
     This program is at most as strong as SAFER  itself.  So,  we\n\
     urge  the user to use this program only after he has assured\n\
     himself that SAFER is strong enough  AND  he  has  read  the\n\
     source  code  of  this  program and its libraries AND he has\n\
     compiled the program himself with a troyan-free compiler. WE\n\
     DO  NOT  GUARANTEE  THAT THIS PROGRAM IS A SECURE ENCRYPTION\n\
     PROGRAM.\n");
#else
    Usage_Error();
#endif
} /* Write_Help_Text */

/*******************************************************************************
*                 E N C R Y P T I O N  /  D E C R Y P T I O N
*******************************************************************************/

/*******************************************************************************
* read one block from 'in_file'. the number of read bytes is returned
*/
#ifndef NOT_ANSI_C
    static unsigned int Get_Block(safer_block_t block)
#else
    static unsigned int Get_Block(block)
    safer_block_t block;
#endif

{   unsigned int i, len;

    if (in_buf_len <= in_buf_pos)
    {
        if (in_buf_len != MAX_BUF_LEN) return 0;
        in_buf_len = fread(in_buf, sizeof(unsigned char), MAX_BUF_LEN, in_file);
        in_buf_pos = 0;
        if (in_buf_len == 0) return 0;
        for (i = in_buf_len; i % SAFER_BLOCK_LEN; i++)
            in_buf[i] = 0;
    }
    for (i = 0; i < SAFER_BLOCK_LEN; i++)
        block[i] = in_buf[in_buf_pos++];
    if (in_buf_pos <= in_buf_len)
        len = SAFER_BLOCK_LEN;
    else
        len = SAFER_BLOCK_LEN + in_buf_len - in_buf_pos;
    input_len += len;
    return len;
} /* Get_Block */

/*******************************************************************************
* write one block to 'out_file'. only the first 'len' bytes are written
*/
#ifndef NOT_ANSI_C
    static void Put_Block(safer_block_t block, unsigned int len)
#else
    static Put_Block(block, len)
    safer_block_t block;
    unsigned int len;
#endif

{   unsigned int i;

    for (i = 0; i < len; i++)
        out_buf[out_buf_len++] = block[i];
    if (MAX_BUF_LEN <= out_buf_len)
    {
        if (fwrite(out_buf, sizeof(unsigned char), MAX_BUF_LEN, out_file) 
            != MAX_BUF_LEN) Error(20, NULL);
        out_buf_len = 0;
    }
} /* Put_Block */

/*******************************************************************************
* write last block to 'out_file' and close 'out_file'
*/
#ifndef NOT_ANSI_C
    static void Close_Output(void)
#else
    static Close_Output()
#endif

{   if (out_buf_len)
    {
        if (fwrite(out_buf, sizeof(unsigned char), out_buf_len, out_file)
            != out_buf_len) Error(20, NULL);
        out_buf_len = 0;
    }
} /* Close_Output */

/*******************************************************************************
* encrypt one block
*/
#ifndef NOT_ANSI_C
    static void Encrypt_Block(safer_block_t block)
#else
    static Encrypt_Block(block)
    safer_block_t block;
#endif

{   int i;

    switch (mode)
    {
        case ECB:
            Safer_Encrypt_Block(block, key, block);
            break;
        case CBC:
            for (i = 0; i < SAFER_BLOCK_LEN; i++)
                block[i] ^= last_block[i];
            Safer_Encrypt_Block(block, key, block);
            for (i = 0; i < SAFER_BLOCK_LEN; i++)
                last_block[i] = block[i];
            break;
        case CFB:
            Safer_Encrypt_Block(last_block, key, last_block);
            for (i = 0; i < SAFER_BLOCK_LEN; i++)
                block[i] = last_block[i] ^= block[i];
            break;
        case OFB:
            Safer_Encrypt_Block(last_block, key, last_block);
            for (i = 0; i < SAFER_BLOCK_LEN; i++)
                block[i] ^= last_block[i];
            break;
        default: break;
    }
} /* Encrypt_Block */

/*******************************************************************************
* decrypt one block
*/
#ifndef NOT_ANSI_C
    static void Decrypt_Block(safer_block_t block)
#else
    static Decrypt_Block(block)
    safer_block_t block;
#endif

{   safer_block_t temp_block;
    int i;

    switch (mode)
    {
        case ECB:
            Safer_Decrypt_Block(block, key, block);
            break;
        case CBC:
            Safer_Decrypt_Block(block, key, temp_block);
            for (i = 0; i < SAFER_BLOCK_LEN; i++)
            {
                temp_block[i] ^= last_block[i];
                last_block[i] = block[i];
                block[i] = temp_block[i];
            }
            break;
        case CFB:
            Safer_Encrypt_Block(last_block, key, temp_block);
            for (i = 0; i < SAFER_BLOCK_LEN; i++)
            {
                last_block[i] = block[i];
                block[i] ^= temp_block[i];
            }
            break;
        case OFB:
            Safer_Encrypt_Block(last_block, key, last_block);
            for (i = 0; i < SAFER_BLOCK_LEN; i++)
                block[i] ^= last_block[i];
            break;
        default: break;
    }
} /* Decrypt_Block */

/*******************************************************************************
* hash one block
*/
#ifndef NOT_ANSI_C
    static void Hash_Block(safer_block_t block)
#else
    static Hash_Block(block)
    safer_block_t block;
#endif

{   int i;
    safer_block_t w;

    Safer_Expand_Userkey(userkey_2, block, nof_rounds, option[STRENGTHENED].set,
                         key);
    Safer_Encrypt_Block(userkey_1, key, w);
    if (mode == TAN)
    {
        Safer_Expand_Userkey(block, w, nof_rounds, option[STRENGTHENED].set,
                             key);
        for (i = 0; i < SAFER_BLOCK_LEN; i++)
        {
            userkey_1[i] ^= w[i];
            w[i] = userkey_2[i];
        }
    }
    else /* mode == ABR */
    {
        Safer_Expand_Userkey(block, userkey_1, nof_rounds,
                             option[STRENGTHENED].set, key);
        for (i = 0; i < SAFER_BLOCK_LEN; i++)
        {
            userkey_1[i] ^= w[i];
            w[i] = userkey_2[i] ^ 0xFF;
        }
    }
    Safer_Encrypt_Block(w, key, w);
    for (i = 0; i < SAFER_BLOCK_LEN; i++)
        userkey_2[i] ^= w[i];
} /* Hash_Block */

/*******************************************************************************
* write the hash value to 'hash_file'
*/
#ifndef NOT_ANSI_C
    static void Write_Hash_Value(void)
#else
    static Write_Hash_Value()
#endif

{   int i;

    for (i = 0; i < SAFER_BLOCK_LEN; i++)
        fprintf(hash_file, "%02X", userkey_1[i]);
    for (i = 0; i < SAFER_BLOCK_LEN; i++)
        fprintf(hash_file, "%02X", userkey_2[i]);
    fprintf(hash_file, "\n");
} /* Write_Hash_Value */

/*******************************************************************************
* store length in bytes in a block
*/
#ifndef NOT_ANSI_C
    void Byte_Length_To_Block(unsigned long int len, safer_block_t block)
#else
    Byte_Length_To_Block(len, block)
    unsigned long int len;
    safer_block_t block;
#endif

{   int i;

    block[0] = (unsigned char)(len << 3 & 0xFF);
    len >>= 5;
    for (i = 1; i < SAFER_BLOCK_LEN; i++)
    {
        block[i] = (unsigned char)(len & 0xFF);
        len >>= 8;
    }
} /* Byte_Length_To_Block */

/*******************************************************************************
* extract length in bytes from a block
*/
#ifndef NOT_ANSI_C
    static void Block_To_Byte_Length(safer_block_t block,
                                     unsigned long int *length)
#else
    static Block_To_Byte_Length(block, length)
    safer_block_t block;
    unsigned long int *length;
#endif

{   unsigned long int len, max_5, max_8;
    int i;

    if (block[0] & 0x7) Error(13, NULL);
    len = 0;
    max_5 = max_8 = ~len;
    max_5 >>= 5;
    max_8 >>= 8;
    for (i = SAFER_BLOCK_LEN - 1; 0 < i; i--)
    {
        if (max_8 < len) Error(13, NULL);
        len <<= 8;
        len |= (unsigned long int)(block[i] & 0xFF);
    }
    if (max_5 < len) Error(13, NULL);
    len <<= 5;
    len |= (unsigned long int)(block[0] & 0xFF) >> 3;
    *length = len;
} /* Block_To_Byte_Length */

/*******************************************************************************
* encrypt / decrypt complete data stream or compute hash value of data stream
*/
#ifndef NOT_ANSI_C
    static void Crypt_Or_Hash_Data_Stream(void)
#else
    static Crypt_Or_Hash_Data_Stream()
#endif

{   unsigned int t, len;
    unsigned long int length;
    safer_block_t temp_block[4];
    safer_block_t block;

    if (option[ENCRYPT].set || option[DECRYPT].set)
    {
        if (userkey_2_set)
            Safer_Expand_Userkey(userkey_1, userkey_2, nof_rounds,
                                 option[STRENGTHENED].set, key);
        else
            Safer_Expand_Userkey(userkey_1, userkey_1, nof_rounds,
                                 option[STRENGTHENED].set, key);
    }
    if (option[ENCRYPT].set) /* encrypt data */
    {
        while ((len = Get_Block(block)) == SAFER_BLOCK_LEN)
        {
            Encrypt_Block(block);
            Put_Block(block, SAFER_BLOCK_LEN);
        }
        if (len) { Encrypt_Block(block); Put_Block(block, SAFER_BLOCK_LEN); }
        Byte_Length_To_Block(input_len, block);
        Encrypt_Block(block);
        Put_Block(block, SAFER_BLOCK_LEN);
        Close_Output();
    }
    else if (option[DECRYPT].set) /* decrypt data */
    {
        if ((len = Get_Block(temp_block[0])) != SAFER_BLOCK_LEN)
        {
            if (len) Error(13, NULL);
            else Error(12, NULL);
        }
        Decrypt_Block(temp_block[0]);
        if ((len = Get_Block(temp_block[1])) != SAFER_BLOCK_LEN)
        {
            if (len) Error(13, NULL);
            Block_To_Byte_Length(temp_block[0], &length);
            if (length) Error(13, NULL);
        }
        else
        {
            Decrypt_Block(temp_block[1]);
            t = 2;
            while ((len = Get_Block(temp_block[t])) == SAFER_BLOCK_LEN)
            {
                Decrypt_Block(temp_block[t]);
                Put_Block(temp_block[(t + 2) & 3], SAFER_BLOCK_LEN);
                t = (t + 1) & 3;
            }
            if (len) Error(13, NULL);
            Block_To_Byte_Length(temp_block[(t + 3) & 3], &length);
            length += 2 * SAFER_BLOCK_LEN;
            if (input_len < length && length <= input_len + SAFER_BLOCK_LEN)
            {
                len = (unsigned int)(length - input_len);
                Put_Block(temp_block[(t + 2) & 3], len);
            }
            else Error(13, NULL);
        }
        Close_Output();
    }
    else /* compute hash value */
    {
        if (option[COPY_AND_HASH].set)
        {
            while ((len = Get_Block(block)) == SAFER_BLOCK_LEN)
            {
                Hash_Block(block);
                Put_Block(block, SAFER_BLOCK_LEN);
            }
            if (len) { Hash_Block(block); Put_Block(block, len); }
            Byte_Length_To_Block(input_len, block);
            Hash_Block(block);
            Close_Output();
        }
        else /* option[HASH].set */
        {
            while ((len = Get_Block(block)) == SAFER_BLOCK_LEN)
                Hash_Block(block);
            if (len) Hash_Block(block);
            Byte_Length_To_Block(input_len, block);
            Hash_Block(block);
        }
        Write_Hash_Value();
    }
} /* Crypt_Or_Hash_Data_Stream */

/*******************************************************************************
* measure encryption speed
*/
#ifndef NOT_ANSI_C
    static void Measure_Encryption_Speed(void)
#else
    static Measure_Encryption_Speed()
#endif

{
#ifdef TIME
    clock_t start_time, end_time;
    float size, duration;
    safer_block_t block;
    safer_key_t key;
    long int i;

    for (i = 0; i < SAFER_BLOCK_LEN; i++) block[i] = 0;
    Safer_Expand_Userkey(block, block, nof_rounds, FALSE, key);
    Safer_Encrypt_Block(block, key, block);
    Safer_Expand_Userkey(block, block, nof_rounds, FALSE, key);
    if ((start_time = clock()) == -1) Error(2, NULL);
    for (i = 163840; i; i--) Safer_Encrypt_Block(block, key, block);
    if ((end_time = clock()) == -1) Error(3, NULL);
    size = 10; /* Mbits */
    duration = (float)(end_time - start_time) / (float)
#ifdef CLOCKS_PER_SEC
               CLOCKS_PER_SEC
#else
#ifdef CLK_TCK
               CLK_TCK
#else
               1000000
#endif
#endif
    ;
    fprintf(stderr,
           "encryption speed = %4.1f Mbits / %4.1f seconds = %6.3f Mb/s\n",
            size, duration, size / duration);
#endif
} /* Measure_Encryption_Speed */

/*******************************************************************************
*                         I N I T I A L I Z A T I O N
*******************************************************************************/

/*******************************************************************************
* read options from string 'str'
*/
#ifndef NOT_ANSI_C
    static void Read_Options(char *str)
#else
    static Read_Options(str)
    char *str;
#endif

{   int opt;

    str++;
    while (*str != '\0')
    {
        for (opt = 0;
             opt < NOF_OPTIONS
             && strncmp(str, option[opt].text, strlen(option[opt].text));
             opt++);
        if (NOF_OPTIONS <= opt || option[opt].set)
            Usage_Error();
        else
        {
            option[opt].set = TRUE;
            str += strlen(option[opt].text);
        }
    }
} /* Read_Options */

/*******************************************************************************
* convert a hex-digit into an integer
*/
#ifndef NOT_ANSI_C
    static unsigned int Hex_To_Int(char ch)
#else
    static unsigned int Hex_To_Int(ch)
    char ch;
#endif

{   if ('0' <= ch && ch <= '9') return ch - '0';
    else if ('a' <= ch  && ch <= 'f') return 10 + (ch - 'a');
    else if ('A' <= ch && ch <= 'F') return 10 + (ch - 'A');
    else if (ch == ':') return COLON;
    else if (ch == '\0') return END_OF_LINE;
    else return ILLEGAL_CHAR;
} /* Hex_To_Int */

/*******************************************************************************
* convert a character into an integer
*/
#ifndef NOT_ANSI_C
    static unsigned int Char_To_Int(char ch)
#else
    static unsigned int Char_To_Int(ch)
    char ch;
#endif

{   if (' ' <= ch && ch <= '~') return ch - ' ';
    else if (ch == '\0') return END_OF_LINE;
    else return ILLEGAL_CHAR;
} /* Char_To_Int */

/*******************************************************************************
* read key and initial value
*/
#ifndef NOT_ANSI_C
    static void Read_Key_Hex_String(char *str)
#else
    static Read_Key_Hex_String(str)
    char *str;
#endif

{   unsigned int val, t;
    char *s;
    int i;

    s = str;
    val = Hex_To_Int(*str++);
    for (i = 0; i < SAFER_BLOCK_LEN && val < NOF_CHARS; i++)
    {
        t = val << 4; val = Hex_To_Int(*str++);
        if (val < NOF_CHARS) { t |= val; val = Hex_To_Int(*str++); }
        userkey_1[i] = (unsigned char)t;
    }
    userkey_2_set = val < NOF_CHARS;
    for (i = 0; i < SAFER_BLOCK_LEN && val < NOF_CHARS; i++)
    {
        t = val << 4; val = Hex_To_Int(*str++);
        if (val < NOF_CHARS) { t |= val; val = Hex_To_Int(*str++); }
        userkey_2[i] = (unsigned char)t;
    }
    if (val < NOF_CHARS) Error(5, s);
    else if (val == COLON)
        val = Hex_To_Int(*str++);
    last_block_set = val < NOF_CHARS;
    for (i = 0; i < SAFER_BLOCK_LEN && val < NOF_CHARS; i++)
    {
        t = val << 4; val = Hex_To_Int(*str++);
        if (val < NOF_CHARS) { t |= val; val = Hex_To_Int(*str++); }
        last_block[i] = (unsigned char)t;
    }
    if (val < NOF_CHARS) Error(6, s);
    else if (val == COLON) Error(8, s);
    else if (val == ILLEGAL_CHAR) Error(4, s);
    while (*s != '\0') *s++ = '\0'; /* clear key */
} /* Read_Key_Hex_String */

/*******************************************************************************
* read key
*/
#ifndef NOT_ANSI_C
    static void Read_Key_String(char *str)
#else
    static Read_Key_String(str)
    char *str;
#endif

{   unsigned int val;
    char *s;
    int i;

    s = str;
    while ((val = Char_To_Int(*str++)) < NOF_CHARS)
    {
        for (i = 0; i < SAFER_BLOCK_LEN; i++)
        {
            val += (unsigned int)userkey_1[i] * NOF_CHARS;
            userkey_1[i] = (unsigned char)(val & 0xFF);
            val >>= 8;
        }
        for (i = 0; i < SAFER_BLOCK_LEN; i++)
        {
            val += (unsigned int)userkey_2[i] * NOF_CHARS;
            userkey_2[i] = (unsigned char)(val & 0xFF);
            val >>= 8;
        }
    }
    if (val == ILLEGAL_CHAR) Error(4, s);
    userkey_2_set = MAX_SHORT_KEY_STRING_LEN < str - s;
    while (*s != '\0') *s++ = '\0'; /* clear key */
} /* Read_Key_String */

/*******************************************************************************
* read number of rounds
*/
#ifndef NOT_ANSI_C
    static void Read_Rounds(char *str)
#else
    static Read_Rounds(str)
    char *str;
#endif

{   unsigned int val;
    char *s;

    s = str;
    nof_rounds = 0;
    while ((val = Hex_To_Int(*str++)) < 10)
    {
        nof_rounds = nof_rounds * 10 + val;
        if (SAFER_MAX_NOF_ROUNDS < nof_rounds) Error(7, s);
    }
    if (val != END_OF_LINE) Error(4, s);
} /* Read_Rounds */

/*******************************************************************************
* check if options are correct and set default options
*/
#ifndef NOT_ANSI_C
    static void Adjust_Options(void)
#else
    static Adjust_Options()
#endif

{   int opt;
#ifdef GETPASS
    char key_str[MAX_SHORT_KEY_STRING_LEN + 1];
    char *str;
    int i;
#endif

    if (option[MEASURE].set)
    {
#ifdef TIME
        if (!option[ROUNDS].set) Usage_Error();
        for (opt = 0; opt < NOF_OPTIONS; opt++)
            if (opt != ROUNDS && opt != MEASURE && option[opt].set)
#endif
                Usage_Error();
    }
    else
    {
        mode = -1;
        for (opt = ECB; opt <= ABR; opt++)
            if (option[opt].set)
                if (mode == -1) mode = opt;
                else Usage_Error();
        if (mode == -1)
        {
            if (option[HASH].set || option[COPY_AND_HASH].set)
                mode = TAN; /* default */
            else
                mode = CBC; /* default */
            option[mode].set = TRUE;
        }
        if ((option[DECRYPT].set && option[ENCRYPT].set)
            || (option[HASH].set && option[COPY_AND_HASH].set)
            || (option[KEY_STRING].set && option[KEY_HEX_STRING].set))
            Usage_Error();
        if (TAN <= mode && mode <= ABR)
        {
            if (!option[ROUNDS].set)
            {
                if (option[STRENGTHENED].set)
                    nof_rounds = SAFER_SK128_DEFAULT_NOF_ROUNDS; /* default */
                else
                    nof_rounds = SAFER_K128_DEFAULT_NOF_ROUNDS; /* default */
                option[ROUNDS].set = TRUE;
            }
            if (!option[HASH].set && !option[COPY_AND_HASH].set)
                option[HASH].set = TRUE; /* default */
            if (last_block_set) Error(14, NULL);
            if (option[DECRYPT].set || option[ENCRYPT].set)
                Usage_Error();
            userkey_2_set = TRUE;
        }
        else /* ECB <= mode && mode <= OFB */
        {
            if (!option[ROUNDS].set)
            {
                if (userkey_2_set)
                    if (option[STRENGTHENED].set)
                        nof_rounds = SAFER_SK128_DEFAULT_NOF_ROUNDS;/* default*/
                    else
                        nof_rounds = SAFER_K128_DEFAULT_NOF_ROUNDS; /* default*/
                else
                    if (option[STRENGTHENED].set)
                        nof_rounds = SAFER_SK64_DEFAULT_NOF_ROUNDS; /* default*/
                    else
                        nof_rounds = SAFER_K64_DEFAULT_NOF_ROUNDS;  /* default*/
                option[ROUNDS].set = TRUE;
            }
            if (!option[DECRYPT].set && !option[ENCRYPT].set)
                option[ENCRYPT].set = TRUE; /* default */
            if (last_block_set && mode == ECB) Error(15, NULL);
            if (!last_block_set && mode != ECB)
                last_block_set = TRUE;
            if (option[HASH].set || option[COPY_AND_HASH].set)
                Usage_Error();
            if (!option[KEY_STRING].set && !option[KEY_HEX_STRING].set)
            {
#ifdef GETPASS
                if ((str = getpass(text[16])) == NULL) Error(19, NULL);
                strncpy(key_str, str, MAX_SHORT_KEY_STRING_LEN);
                key_str[MAX_SHORT_KEY_STRING_LEN] = '\0';
                while (*str != '\0') *str++ = '\0'; /* clear key */
                if ((str = getpass(text[17])) == NULL) Error(19, NULL);
                if (strcmp(key_str, str))
                {
                    while (*str != '\0') *str++ = '\0'; /* clear key */
                    for (i = 0; i < MAX_SHORT_KEY_STRING_LEN; i++)
                        key_str[i] = '\0';
                    Error(18, NULL);
                }
                while (*str != '\0') *str++ = '\0'; /* clear key */
                option[KEY_STRING].set = TRUE;
                Read_Key_String(key_str);
#else
                Usage_Error();
#endif
            }
        }
        
    }
} /* Adjust_Options */

/*******************************************************************************
* open an existing input file
*/
#ifndef NOT_ANSI_C
    static void Open_Input_File(char *file_name, FILE **file)
#else
    static Open_Input_File(file_name, file)
    char *file_name;
    FILE **file;
#endif

{   if (strcmp(file_name, "-")
        && (*file = fopen(file_name, "rb")) == NULL)
        Error(0, file_name);
} /* Open_Input_File */

/*******************************************************************************
* create a new output file
*/
#ifndef NOT_ANSI_C
    static void Create_Output_File(char *file_name, FILE **file)
#else
    static Create_Output_File(file_name, file)
    char *file_name;
    FILE **file;
#endif

{   if ((*file = fopen(file_name, "wb")) == NULL)
        Error(1, file_name);
} /* Create_Output_File */

/*******************************************************************************
* show current state information on 'stderr'
*/
#ifndef NOT_ANSI_C
    static void Show_State(void)
#else
    static Show_State()
#endif

{   int i;

    fprintf(stderr, "Options:      ");
    for (i = 0; i < NOF_OPTIONS; i++)
        if (option[i].set)
        {
            fprintf(stderr, " -%s", option[i].text);
            if (i == ROUNDS)
                fprintf(stderr, " %d", nof_rounds);
        }
    fprintf(stderr, "\nKey:           z    =");
    for (i = 0; i < SAFER_BLOCK_LEN; i++)
        fprintf(stderr, " %02X", (unsigned int)userkey_1[i]);
    if (userkey_2_set)
        for (i = 0; i < SAFER_BLOCK_LEN; i++)
            fprintf(stderr, " %02X", (unsigned int)userkey_2[i]);
    if (last_block_set)
    {
        fprintf(stderr, "\nInitial value: y[0] =");
        for (i = 0; i < SAFER_BLOCK_LEN; i++)
            fprintf(stderr, " %02X", (unsigned int)last_block[i]);
    }
    fprintf(stderr, "\n");
} /* Show_State */

/*******************************************************************************
*                                    M A I N
*******************************************************************************/
#ifndef NOT_ANSI_C
    int main(int argc, char *argv[])
#else
    int main(argc, argv)
    int argc;
    char *argv[];
#endif

{   int old_opt_set[NOF_OPTIONS];
    int i, opt;

    Init_Module();
    argv++; argc--;

    /* read the options given on command line */
    while (0 < argc && argv[0][0] == '-' && argv[0][1] != '\0')
    {
        for (i = 0; i < NOF_OPTIONS; i++)
            old_opt_set[i] = option[i].set;
        Read_Options(*argv++); argc--;
        opt = -1;
        for (i = 0; i < NOF_OPTIONS; i++)
             if (option[i].read_func != NULL && option[i].set != old_opt_set[i])
                 if (opt == -1) opt = i;
                 else Usage_Error();
        if (opt != -1)
            if (0 < argc) { (*option[opt].read_func)(*argv++); argc--; }
            else Usage_Error();
    }
    if (option[WRITE_HELP].set)
    {
        Write_Help_Text();
        Free_Module();
        return 0;
    }
    if ((option[MEASURE].set && 0 < argc)
        || (option[COPY_AND_HASH].set && 3 < argc)
        || (!option[COPY_AND_HASH].set && 2 < argc))
        Error(9, NULL);
    if ((1 < argc && !strcmp(argv[0], argv[1]))
        || ((2 < argc && !strcmp(argv[0], argv[2]))))
        Error(10, NULL);
    if (2 < argc && !strcmp(argv[1], argv[2]))
        Error(11, NULL);
    Adjust_Options();

    /* open the needed input and output files */
    in_file = stdin;
    out_file = hash_file = stdout;
    if (0 < argc) { Open_Input_File(*argv++, &in_file); argc--; }
    if (option[COPY_AND_HASH].set)
    {
        if (1 < argc) { Create_Output_File(*argv++, &out_file); argc--; }
        if (0 < argc) { Create_Output_File(*argv++, &hash_file); argc--; }
        else hash_file = stderr;
    }
    else if (option[HASH].set)
    {
        if (0 < argc) { Create_Output_File(*argv++, &hash_file); argc--; }
    }
    else
    {
        if (0 < argc) { Create_Output_File(*argv++, &out_file); argc--; }
    }
    if (0 < argc) Error(9, *argv);

    /* do the work */
    if (option[VERBOSE].set)
        Show_State();
    if (option[MEASURE].set)
        Measure_Encryption_Speed();
    else
        Crypt_Or_Hash_Data_Stream();

    /* close opened files */
    if (in_file != stdin) fclose(in_file);
    if (out_file != stdout) fclose(out_file);
    if (hash_file != stdout && hash_file != stderr) fclose(hash_file);

    Free_Module();
    return 0;
} /* main */

/******************************************************************************/
