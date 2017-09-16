/* sapptest.cpp
   
   Sapphire stream cipher test program in C++
   Written by Michael Paul Johnson 20 December 1994 and donated
   to the Public Domain.  This program comes with no warranty of
   any kind.  There is no warranty of any kind on the Sapphire
   Stream Cipher.  Use it at your own risk.

   This program is a test driver for the Sapphire Stream Cipher,
   which is represented in the sapphire object.  This program
   will encrypt or decrypt a file based on pass phrase key on the
   command line.  The user interface is a simple positional command
   line interface:

     First parameter:   E to Encrypt, D to Decrypt, H to compute
                        Hash or cryptographic check value.
     Second parameter:  Input file name
     Third parameter:   Output file name
     Fourth parameter:  Pass phrase

   There is minimal error checking.  A serious application should
   do more error checking and provide for such things as bad pass
   phrase detection.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sapphire.h"

int encryptit;
FILE *infile;
FILE *outfile;
sapphire stream_cipher;
char user_key[256];
unsigned char hash[20];
unsigned char b;
int count;

void help(void)
    {
    puts("Sapphire test program written by Michael Paul Johnson"
         " 2 January 1995\n"
         "and donated to the Public Domain.  No warranty,"
         " expressed or implied.\n"
         "Use this program at your own risk.\n"
         "Don't forget your passphrase.  No passphrase, no "
         "data.\n\n"
         "Syntax:\n"
         "stest E|D|H inname outname passphrase\n"
         "  E = Encrypt\n"
         "  D = Decrypt\n"
         "  H = compute keyed cryptographic Hash\n"
         "  passphrase is optional for hash computation.\n");
    exit(1);
    }

int main(int argc, char **argv)
    {
    int i;

    if (argc < 3)
        {
        help();
        }
    if ((argv[1][0] == 'E') || (argv[1][0] == 'e'))
        encryptit = 1;
    else if ((argv[1][0] == 'H') || (argv[1][0] == 'h'))
        encryptit = 2;
    else if ((argv[1][0] == 'D') || (argv[1][0] == 'd'))
        encryptit = 0;
    else
        help();
    infile = fopen(argv[2], "rb");
    outfile = fopen(argv[3], "wb");
    if (argc > 4)
        strcpy(user_key, argv[4]);
    else
        user_key[0] = 0;
    for (i=5;i<argc;i++)
        {
        strcat(user_key, " ");
        strcat(user_key, argv[i]);
        }
    stream_cipher.initialize((unsigned char *)(user_key),
                             strlen(user_key));
    if (encryptit == 1)
        {
        do
            {
            count = fread(&b, 1, 1, infile);
            if (count)
                {
                b=stream_cipher.encrypt(b);
                fwrite(&b, 1, 1, outfile);
                }
            }
        while (count);
        }
    else if (encryptit == 0)
        {
        do
            {
            count = fread(&b, 1, 1, infile);
            if (count)
                {
                b=stream_cipher.decrypt(b);
                fwrite(&b, 1, 1, outfile);
                }
            }
        while (count);
        }
    else
        {
        do
            {
            count = fread(&b, 1, 1, infile);
            if (count)
                {
                b=stream_cipher.encrypt(b);
                }
            }
        while (count);
        stream_cipher.hash_final(hash);
        fprintf(outfile, "Check value for %s is:\r\n", argv[2]);
        for (i=0;i<20;i++)
            fprintf(outfile,"%02X", hash[i]);
        fprintf(outfile,"\r\n");
        }
    stream_cipher.burn();
    return 0;
    }

