/* DLOCK2.CPP -- Diamond2 Block Cipher Demonstration program.

This program is used to test and validate the implementation of the
Diamond2 Block Cipher in software.  It can also encrypt or decrypt
files using ten round Diamond2 in cyphertext feedback mode and a key
from a command line parameter, environment variable, or keyboard.

There are lots of ways to improve upon this program:  (1) add key
management, (2) use more clever chaining methods, (3) add header
information to the encrypted file to allow the decryption program to
automatically determine the proper algorithm(s) needed to decrypt and
decompress, (4) add data compression and/or noise addition, (5)
improve the user interface, (6) allow selection of other algorithms,
and (7) probably more that I haven't mentioned.  In spite of the lack
of the above possible improvements, I think this program is useful to
(1) demonstrate and test Diamond2 Block Cipher implementations, and
(2) encrypt some data where manual key management is acceptable and
the file length must be preserved.

DLOCK2.CPP is Copyright (C) 1995 Michael Paul Johnson.
All rights reserved.  No warranty.

This program is free software; you can redistribute it and/or modify
it provided that the origin of this software is not misrepresented,
and provided that all differences between the author's distribution
and yours are clearly documented, and provided that you retain this
copyright notice in the source code.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

You are responsible for compliance with all applicable law that may
pertain to the use, distribution, and export of this program.  This
program might be considered a munition by the U. S. Department of
state, so please handle it with care.  Don't break any export laws.

Caution: this program has been know to exist in both matter and
energy states.  Since the conversion of matter to energy can be quite
hazardous, and sometims results in widespread devastation, you must
promise not to destroy any cities with this program.

If you don't agree to all of the above terms, you are required to
destroy all of your copies of this program.

The author can be reached at m.p.johnson@ieee.org, mpj@csn.net,
mpj@netcom.com, CompuServe 71331,2332, or at PO BOX 1151, LONGMONT CO
80502-1151, USA.

*/

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#ifdef UNIX
#include <memory.h>
#include <termio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/uio.h>
#define O_BINARY 0
#else
#include <conio.h>
#include <io.h>
#include <mem.h>
#endif
#include "def.h"
#include "diamond2.h"
#include "crc.h"

#define PATHSIZE 82
#define PASS_SIZE 256
#define CHUNK 16384
/* CHUNK must be a multiple of 16.  CHUNK is the number of bytes read from
disk or written to disk at a time when encrypting or decrypting a file. */

static byte encryption_key[32] =
    {0xE8, 0x34, 0xFD, 0xB9, 0x33, 0xC5, 0x02, 0x92,
     0x3D, 0x92, 0xBC, 0x9E, 0x14, 0x36, 0x8E, 0x70,
     0xD4, 0x1C, 0x66, 0xCB, 0xDF, 0x36, 0x15, 0x50,
     0x33, 0xA6, 0x6E, 0x07, 0xE6, 0xCC, 0x6D, 0x8D};

static uint keysize;    /* Number of bytes of key to use. */
static uint rounds;     /* Number of rounds to use with Diamond2. */
#ifdef MPJs_Copy
static uint literounds; /* Number of rounds to use with Diamond2 Lite. */
#endif
static int blocksize;   /* Block size=8 for Diamond2 Lite or 16 for Diamond2. */

static byte seed[16] = {0x5A, 0x8D, 0x87, 0x2D, 0x31, 0xEE, 0xDD, 0xE6,
                        0x3F, 0xC4, 0x6F, 0x6C, 0x36, 0x45, 0x6D, 0x8E};

static byte ciphertext[16];
static byte plaintext[16];

static boolean generate, end_of_file, validate_file, startpass, encryptit,
    decryptit, verbose;
static char testfilename[] = "DIAMOND2.DAT";

static char infilename[PATHSIZE] = "";
static char outfilename[PATHSIZE] = "";
static byte passphrase[PASS_SIZE];

FILE *f;

#ifdef MPJs_Copy
void generate_test_data(void)
    {
    int i;

    f = fopen(testfilename, "wt");
    if (!f)
        {
        printf("Can't open %s for writing.\n", testfilename);
        exit(2);
        }
    fprintf(f, "# Diamond2/Diamond2 lite validation data file.\n"
        "# Format:\n"
        "#    Everything between # and end of line is a comment.\n"
        "#    Numbers are all in hexadecimal (using upper case letters).\n"
        "#    Data sets are in groups of 6 numbers, separated by white space:\n"
        "#    Block size (10 or 8), rounds, key size, key, plain text, cipher text.\n\n");

    rounds = 15;
    literounds = 30;
    for (keysize = 32; keysize >= 8; keysize--)
        {

        /* Generate Diamond2 Lite test data. */

        blocksize = 8;
        set_diamond2_key(encryption_key, keysize, literounds, true, blocksize);
        fprintf(f, "%02X %02X %02X ", blocksize, literounds, keysize);
        printf("Block size: %02X  Rounds: %02X  Key size: %02X\n",
            blocksize, literounds, keysize);
        for (i=0; i < keysize; i++)
            fprintf(f, "%02X", encryption_key[i]);
        fprintf(f, "\n   ");
        for (i=0; i < blocksize; i++)
            fprintf(f, "%02X", seed[i]);
        fprintf(f, " ");
        lite2_encrypt_block(seed, ciphertext);
        lite2_decrypt_block(ciphertext, plaintext);
        for (i = 0; i < blocksize; i++)
            {
            fprintf(f, "%02X", ciphertext[i]);
            if (plaintext[i] != seed[i])
                {
                printf("Reversal failure!\n");
                fputs("\nReversal failure!", f);
                fclose(f);
                exit(4);
                }
            }
        fputs("\n", f);

        /* Generate Diamond2 test data. */

        blocksize = 16;
        set_diamond2_key(encryption_key, keysize, rounds, true, blocksize);
        fprintf(f, "%02X %02X %02X ", blocksize, rounds, keysize);
        printf("Block size: %02X  Rounds: %02X  Key size: %02X\n",
            blocksize, rounds, keysize);
        for (i=0; i < keysize; i++)
            fprintf(f, "%02X", encryption_key[i]);
        fprintf(f, "\n   ");
        for (i=0; i < blocksize; i++)
            fprintf(f, "%02X", seed[i]);
        fprintf(f, " ");
        diamond2_encrypt_block(seed, ciphertext);
        diamond2_decrypt_block(ciphertext, plaintext);
        for (i = 0; i < blocksize; i++)
            {
            fprintf(f, "%02X", ciphertext[i]);
            if (plaintext[i] != seed[i])
                {
                printf("Reversal failure!\n");
                fputs("\nReversal failure!", f);
                fclose(f);
                exit(4);
                }
            }
        fputs("\n\n", f);

        /* Set up for next set of data. */

        diamond2_encrypt_block(ciphertext, seed);
        diamond2_encrypt_block(encryption_key, encryption_key);
        diamond2_encrypt_block(encryption_key+16, encryption_key+16);
        rounds -= 3;
        if (rounds < 5) rounds += 11;
        literounds -= 3;
        if (literounds < 4) literounds += 13;
        }
    fclose(f);
    }
#endif

int read_hex_char(void)
    {
    static int saved_char = 0;
    static int white_space = 1;
    int ch;

    if (saved_char)
        {
        ch = saved_char;
        saved_char = 0;
        }
    else if (white_space)
        {
        do  /* Skip leading white space and uninteresting characters. */
            {
            ch = fgetc(f);
            if (ch == '#')
                {   /* Skip comment line. */
                do
                    {
                    ch = fgetc(f);
                    }
                while ((ch != EOF) && (ch != '\n') && (ch != '\r'));
                }
            }
        while ((ch != EOF) && ((ch < '0') || (ch > 'F') || ((ch > '9') && (ch < 'A'))));
        white_space = 0;
        }
    else
        {
        ch = fgetc(f);
        if (ch == '#')
            {   /* Skip comment line. */
            do
                {
                ch = fgetc(f);
                }
            while ((ch != EOF) && (ch != '\n') && (ch != '\r'));
            }
        if ((ch < '0') || (ch > 'F') || ((ch > '9') && (ch < 'A')))
            {
            ch = 0;
            white_space = 1;
            }
        }
    if (ch == EOF)
        {
        end_of_file = true;
        ch = 0;
        }
    return ch;
    }

uint from_hex(int hex_character)
    {
    hex_character -= '0';
    if (hex_character > 9)
        hex_character -= 7;
    return (uint)hex_character;
    }

uint read_uint(void)
    {
    int ch, i;
    uint u;
 
    u = 0;
    i = 0;
    do
        {
        ch = read_hex_char();
        if (ch)
            {
            u = (u << 4) + from_hex(ch);
            }
        if (++i > 5)
            {
            puts("Unexpected character reading unsigned integer.");
            exit(6);
            }
        }
    while (ch && (!end_of_file));
    return u;
    }

void read_hex_block(byte *dest, uint numbytes)
    {
    uint u;
    int ch;

    for (u = 0; u < numbytes; u++)
        {
        dest[u] = from_hex(read_hex_char());
        dest[u] = (dest[u] << 4) + from_hex(read_hex_char());
        }
    ch = read_hex_char();
    if ((ch != 0) && (ch != EOF))
        {
        puts("Unexpected input.");
        exit(7);
        }
    }

void validate_test_data(void)
    {
    int i;

    end_of_file = false;
    f = fopen(testfilename, "rt");
    if (!f)
        {
        printf("Unable to open %s\n", testfilename);
        exit(5);
        }
    while (!end_of_file)
        {
        blocksize = read_uint();
        if (end_of_file) return;
        rounds = read_uint();
        keysize = read_uint();
        read_hex_block(encryption_key, keysize);
        read_hex_block(plaintext, blocksize);
        read_hex_block(ciphertext, blocksize);
        if (blocksize == 8)
            {
            printf("Testing Diamond2 Lite");
            }
        else if (blocksize ==  16)
            {
            printf("Testing Diamond2");
            }
        else
            {
            puts("Unexected data.");
            exit(9);
            }
        printf(" with %u rounds, %u byte key.\n", rounds, keysize);
        set_diamond2_key(encryption_key, keysize, rounds, true, blocksize);
        if (blocksize == 16)
            {
            diamond2_encrypt_block(plaintext, seed);
            for (i=0; i<blocksize; i++)
                {
                if (seed[i] != ciphertext[i])
                    {
                    puts("Encryption error.");
                    exit(8);
                    }
                }
            diamond2_decrypt_block(ciphertext, seed);
            for (i=0; i<blocksize; i++)
                {
                if (seed[i] != plaintext[i])
                    {
                    puts("Decryption error.");
                    exit(8);
                    }
                }
            }
        else
            {
            lite2_encrypt_block(plaintext, seed);
            for (i=0; i<blocksize; i++)
                {
                if (seed[i] != ciphertext[i])
                    {
                    puts("Encryption error.");
                    exit(8);
                    }
                }
            lite2_decrypt_block(ciphertext, seed);
            for (i=0; i<blocksize; i++)
                {
                if (seed[i] != plaintext[i])
                    {
                    puts("Decryption error.");
                    exit(8);
                    }
                }
            }
        }
    fclose(f);
    }

static void get_pass_phrase(char *key, uint maxlength)
    {
    int ch;
    uint keypos;
	char check_pw[PASS_SIZE];

    puts("Please enter your pass phrase (case sensitive):");
    keypos = 0;
    key[0] = 0;
    do
        {
#ifdef UNIX
        ch = getchar();
#else
        ch = getch();
        if (!ch) ch = 0x100 + getch();
#endif
        if (((ch == 8) || (ch == 127)) && keypos)
            {
            key[--keypos] = 0;
            printf("\x08 \x08");
            }
        else if ((ch == 27) || (ch == 3))
            {
            key[0] = 0;
            }
        else if ((ch != 13) && (ch != 10) && (ch != 8) && (ch != 127))
            {
            printf("*");
            key[keypos++] = (char) ch;
            key[keypos] = 0;
            }
        }
    while ((ch != 13) && (ch != 10) && (ch != 3) && (ch != 27) && (keypos < (maxlength-1)));
    puts("\r                                                                              ");
	if (encryptit)
		{
		puts("Please verify your pass phrase (case sensitive):");
		keypos = 0;
		check_pw[0] = 0;
		do
			{
#ifdef UNIX
            ch = getchar();
#else
            ch = getch();
            if (!ch) ch = 0x100 + getch();
#endif
            if (((ch == 8) || (ch == 127)) && keypos)
				{
				check_pw[--keypos] = 0;
				printf("\x08 \x08");
				}
			else if ((ch == 27) || (ch == 3))
				{
				check_pw[0] = 0;
				}
			else if ((ch != 13) && (ch != 10) && (ch != 8) && (ch != 127))
				{
				printf("*");
				check_pw[keypos++] = (char) ch;
				check_pw[keypos] = 0;
				}
			}
		while ((ch != 13) && (ch != 10) && (ch != 3) && (ch != 27) && (keypos < (maxlength-1)));
		puts("\r                                                                              \r");
		if (strcmp(check_pw, key))
			{
			puts("Pass phrases didn't match.  Please try again.");
			key[0] = 0;
			}
		memset(check_pw,0,PASS_SIZE);
		}
	}

void help(void)
    {
    puts("\nCopyright (C) 1995 Michael Paul Johnson.\n"
        "All rights reserved.  No warranty.\n\n"
        "To test Diamond2 and Diamond2 Lite against validation data:\n"
        "  DLOCK2 /T\n"
#ifdef MPJs_Copy
        "To generate new validation data set:\n"
        "  DLOCK2 /G\n"
#endif
        "To encrypt a file:\n"
        "  DLOCK2 /E [/S] infilename outfilename [/Ppass phrase | /Kkeyfile]\n"
        "To decrypt a file:\n"
        "  DLOCK2 /D [/S] infilename outfilename [/Ppass phrase | /Kkeyfile]\n"
        "/S = Silent mode (minimal screen output).\n");
    exit(1);
    }

int encrypt_file(char *inname, char *outname, uint keysize, byte *key)
    {
    int infile, outfile, bytesinbuf, i, blockpos;
    byte *buf;
    byte lastciphertext[16];
    ulong bytesdone;

    buf = (byte*) malloc(CHUNK);
    if (!buf)
        {
        puts("Out of memory.");
        return(3);
        }
    infile = open(inname, O_RDONLY | O_BINARY);
    if (infile < 0)
        {
        printf("Can't open %s\n", inname);
        return(13);
        }
    outfile = open(outname,O_WRONLY|O_EXCL|O_CREAT|O_BINARY,S_IREAD|S_IWRITE);
    if (outfile < 0)
        {
        printf("Can't open %s\n", outname);
        puts("Output file cannot already exist.");
        return(14);
        }
    bytesdone = 0;
    set_diamond2_key(key, keysize, 10, false, 16);
    memset(lastciphertext, 0, 16);
    diamond2_encrypt_block(lastciphertext, lastciphertext);
    blockpos = 0;
    do
        {
        bytesinbuf = read(infile, (char *)buf, CHUNK);
        for (i = 0; i<bytesinbuf; i++)
            {
            buf[i] ^= lastciphertext[blockpos++];
            if (blockpos >= 16)
                {
                blockpos = 0;
                diamond2_encrypt_block(buf + i - 15, lastciphertext);
                }
            }
        if (bytesinbuf)
            {
            if (write(outfile, (char *)buf, bytesinbuf) != bytesinbuf)
                {
                printf("Error writing to %s\n", outname);
                return(15);
                }
            bytesdone += bytesinbuf;
            if (verbose) printf("\r%lu bytes encrypted.  ", bytesdone);
            }
        }
    while (bytesinbuf == CHUNK);
    if (close(outfile)) printf("Error closing %s\n", outname);
    close(infile);
    diamond2_done();
    if (verbose) puts("");
    return 0;
    }

int decrypt_file(char *inname, char *outname, uint keysize, byte *key)
    {
    int infile, outfile, bytesinbuf, i, blockpos;
    byte *buf;
    byte lastciphertext[16];
    byte thisciphertext[16];
    ulong bytesdone;

    buf = (byte*) malloc(CHUNK);
    if (!buf)
        {
        puts("Out of memory.");
        return(3);
        }
    infile = open(inname, O_RDONLY | O_BINARY);
    if (infile < 0)
        {
        printf("Can't open %s\n", inname);
        return(13);
        }
    outfile = open(outname,O_WRONLY|O_EXCL|O_CREAT|O_BINARY,S_IREAD|S_IWRITE);
    if (outfile < 0)
        {
        printf("Can't open %s\n", outname);
        puts("Output file cannot already exist.");
        return(14);
        }
    bytesdone = 0;
    set_diamond2_key(key, keysize, 10, false, 16);
    memset(lastciphertext, 0, 16);
    diamond2_encrypt_block(lastciphertext, lastciphertext);
    blockpos = 0;
    do
        {
        bytesinbuf = read(infile, (char *)buf, CHUNK);
        for (i = 0; i<bytesinbuf; i++)
            {
            thisciphertext[blockpos] = buf[i];
            buf[i] ^= lastciphertext[blockpos++];
            if (blockpos >= 16)
                {
                blockpos = 0;
                diamond2_encrypt_block(thisciphertext, lastciphertext);
                }
            }
        if (bytesinbuf)
            {
            if (write(outfile, (char *)buf, bytesinbuf) != bytesinbuf)
                {
                printf("Error writing to %s\n", outname);
                return(15);
                }
            bytesdone += bytesinbuf;
            printf("\r%lu bytes decrypted.  ", bytesdone);
            }
        }
    while (bytesinbuf == CHUNK);
    if (close(outfile)) printf("Error closing %s\n", outname);
    close(infile);
    diamond2_done();
    if (verbose) puts("");
    return 0;
    }

int main(int argc, char** argv)
    {
    int i, c, keyfile;
    uint keysize;
    char *p;
    char keyfilename[PATHSIZE];

    generate = validate_file = startpass = encryptit = decryptit = false;
    verbose = true;
    keysize = 0;
    keyfilename[0] = 0;
    passphrase[0] = 0;

    for (i=1;i<argc;i++)
        {
        if ((!startpass) && (argv[i][0] == '-') || (argv[i][0] == '/'))
            {
            c = argv[i][1] | 0x20;
            switch (c)
                {
                case 'd':
                    decryptit = true;
                    encryptit = false;
                    break;
                case 'e':
                    decryptit = false;
                    encryptit = true;
                    break;
#ifdef MPJs_Copy
                case 'g':
                    generate = true;
                    break;
#endif
                case 'k':
                    strcpy(keyfilename, argv[i] + 2);
                    break;
                case 'p':
                    startpass = true;
                    strcpy((char *) passphrase, argv[i] + 2);
                    keysize = strlen((char *)passphrase);
                    break;
                case 's':
                    verbose = false;
                    break;
                case 't':
                    validate_file = true;
                    break;
                default:
                    help();
                    break;
                }
            }
        else if (startpass)
            {
            strcat((char *) passphrase, " ");
            strcat((char *) passphrase, argv[i]);
            keysize = strlen((char *)passphrase);
            }
        else if (infilename[0] == 0)
            {
            strcpy(infilename, argv[i]);
            }
        else if (outfilename[0] == 0)
            {
            strcpy(outfilename, argv[i]);
            }
        else
            {
            help();
            }
        }
    if (!(generate || validate_file || encryptit || decryptit))
        help();
#ifdef MPJs_Copy
    if (generate) generate_test_data();
#endif
    if (generate || validate_file) validate_test_data();
    if (encryptit || decryptit)
        {
        if (!outfilename[0])
            help();
        if (keysize)
            {
            if (verbose)
                puts("Using pass phrase from command line.");
            }
        else if (keyfilename[0])
            {
            keyfile = open(keyfilename, O_RDONLY|O_BINARY);
            if (keyfile >= 0)
                {
                keysize = read(keyfile, (char *)passphrase, PASS_SIZE);
                close(keyfile);
                if (verbose)
                    {
                    if (keysize)
                        printf("Using pass phrase from %s\n", keyfilename);
                    else
                        printf("No key read from file %s\n", keyfilename);
                    }
                }
            else
                {
                printf("Can't open %s\n", keyfilename);
                }
            }
        if (!keysize)
            {
            p = getenv("DLOCK_KEY");
            if (p)
                {
                strcpy((char *) passphrase, p);
                keysize = strlen((char *)passphrase);
                if (verbose)
                    puts("Using pass phrase from DLOCK_KEY environment variable.");
                }
            else
                {
                get_pass_phrase((char *) passphrase, PASS_SIZE);
                keysize = strlen((char *)passphrase);
                }
            }
        if (!keysize)
            {
            puts("Pass phrase required to encrypt or decrypt.");
            return(10);
            }
        if ((keysize < 6) && encryptit)
            {
            puts("WARNING: PASS PHRASE IS TOO SHORT FOR SECURITY!");
            }
        if (encryptit)
            {
            if (verbose)
                printf("Encrypting %s to %s\n", infilename, outfilename);
            return(encrypt_file(infilename, outfilename, keysize, passphrase));
            }
        else
            {
            if (verbose)
                printf("Decrypting %s to %s\n", infilename, outfilename);
            return(decrypt_file(infilename, outfilename, keysize, passphrase));
            }
        }
    return 0;
    }

