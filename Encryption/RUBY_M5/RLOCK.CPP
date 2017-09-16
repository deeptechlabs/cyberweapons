/* RLOCK.CPP -- Ruby Encryption Demonstration program.

This program is used to test and validate the implementation of the
Ruby encryption algorithm in software.  It can also encrypt or
decrypt files using Ruby in electronic codebook mode and a key from a
command line parameter, environment variable, or keyboard.

RLOCK.CPP is Copyright (C) 1994-1996 Michael Paul Johnson.
All rights reserved.  No warranty.

This program is free software; you can redistribute it as a and/or
modify it as long as you retain this notice in the source code and
you don't misrepresent the source of this program.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

Export or use of this program might be restricted by law.

The author can be reached at m.p.johnson@ieee.org, or at PO BOX 1151,
LONGMONT CO 80502-1151, USA.
*/

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <time.h>
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
#include <dos.h>
#endif
#include "def.h"
#include "ruby.h"

#define PATHSIZE 82
#define PASS_SIZE 256
#define BLOCK_SIZE 8
#define CHUNK 16384
/*
CHUNK must be a multiple of BLOCK_SIZE.  CHUNK is the number of bytes read
from disk or written to disk at a time when encrypting or decrypting a file.
*/

static boolean generate, validate_file, startpass, encryptit,
    decryptit, verbose;

static char infilename[PATHSIZE] = "";
static char outfilename[PATHSIZE] = "";
static byte passphrase[PASS_SIZE];

FILE *f;

static void get_pass_phrase(char *key, uint maxlength)
    {
    int ch;
    uint keypos;

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
    }

void help(void)
    {
    puts("\nCopyright (C) 1994-1996 Michael Paul Johnson.\n"
        "All rights reserved.  No warranty.\n\n"
        "To encrypt or decrypt a file:\n"
        "  RLOCK [/S] [/D|/E] infilename outfilename [/Ppass phrase | /Kkeyfile]\n"
        "/E = Encrypt\n"
        "/D = Decrypt\n"
        "/S = Silent mode (minimal screen output).\n");
    exit(1);
    }

int encrypt_file(char *inname, char *outname, uint keysize, byte *key)
    {
    int infile, outfile, bytesinbuf, i, blockpos;
    byte *buf;
    byte ruby_key[BLOCK_SIZE];
    byte lastciphertext[BLOCK_SIZE];
    ulong bytesdone;

    buf = (byte*) malloc(CHUNK);
    if (!buf)
        {
        puts("Out of memory.");
        return(3);
        }
    ruby_hash_init();
    ruby_hash_update(key, keysize);
    ruby_hash_final(ruby_key);
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
    memset(lastciphertext, 0, BLOCK_SIZE);
    ruby_crypt(lastciphertext, ruby_key, lastciphertext);
    blockpos = 0;
    do
        {
        bytesinbuf = read(infile, (char *)buf, CHUNK);
        for (i = 0; i<bytesinbuf; i++)
            {
            buf[i] ^= lastciphertext[blockpos++];
            if (blockpos >= BLOCK_SIZE)
                {
                blockpos = 0;
                ruby_crypt(buf + i - (BLOCK_SIZE - 1), ruby_key, lastciphertext);
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
    if (verbose) puts("");
    return 0;
    }

int decrypt_file(char *inname, char *outname, uint keysize, byte *key)
    {
    int infile, outfile, bytesinbuf, i, blockpos;
    byte *buf;
    byte ruby_key[BLOCK_SIZE];
    byte lastciphertext[BLOCK_SIZE];
    byte thisciphertext[BLOCK_SIZE];
    ulong bytesdone;

    buf = (byte*) malloc(CHUNK);
    if (!buf)
        {
        puts("Out of memory.");
        return(3);
        }
    ruby_hash_init();
    ruby_hash_update(key, keysize);
    ruby_hash_final(ruby_key);
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
    memset(lastciphertext, 0, BLOCK_SIZE);
    ruby_crypt(lastciphertext, ruby_key, lastciphertext);
    blockpos = 0;
    do
        {
        bytesinbuf = read(infile, (char *)buf, CHUNK);
        for (i = 0; i<bytesinbuf; i++)
            {
            thisciphertext[blockpos] = buf[i];
            buf[i] ^= lastciphertext[blockpos++];
            if (blockpos >= BLOCK_SIZE)
                {
                blockpos = 0;
                ruby_crypt(thisciphertext, ruby_key, lastciphertext);
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
    if (verbose) puts("");
    return 0;
    }

unsigned int bitcount(byte *b, unsigned int numbytes = 8)
    {
    unsigned int count, bytenum;
    byte mask;

    count = 0;
    for (bytenum=0;bytenum<numbytes;bytenum++)
        {
        for (mask = 1; mask; mask <<= 1)
            {
            if (mask & b[bytenum])
                count++;
            }
        }
    return count;
    }

void rotate_mask(byte *mask)
    {
    int i;

    for (i=0;i<8;i++)
        {
        if (mask[i])
            {
            mask[i] >>= 1;
            if (!mask[i])
                {
                if (i==7)
                    mask[0] = 0x80;
                else
                    mask[i+1] = 0x80;
                }
            }
        }
    }

void xorbytes(byte *A, byte *B, byte *C)
    {
    int i;
    for (i=0;i<8;i++)
        {
        C[i] = A[i] ^ B[i];
        }
    }

void testit(void)
    {
    int i, j;
    unsigned countp, countk;
    unsigned long totalp, totalk;
    time_t t;
    byte key[8];
    byte mask[8];
    byte plain[8];
    byte X[8];
    byte Y[8];
    byte Z[8];
    byte T[8];
    FILE *f;

    randomize();
    memset(mask, 0, 8);
    mask[0] = 0x80;
    totalp = totalk = 0;
    f=fopen("rlock.rpt", "wt");
    for (j=0;j<10000;j++)
        {
        for (i=0;i<8;i++)
            {
            key[i] = random(256);
            plain[i] = random(256);
            }
        ruby_crypt(plain, key, X);
        xorbytes(plain, mask, plain);
        ruby_crypt(plain, key, Y);
        xorbytes(key, mask, key);
        ruby_crypt(plain, key, Z);
        rotate_mask(mask);
        xorbytes(X,Y,T);
        countp = bitcount(T);
        totalp += countp;
        xorbytes(Y,Z,T);
        countk = bitcount(T);
        totalk += countk;
        fprintf(f,"%2u %2u\n", countp, countk);
        }
    fprintf(f,"-- --\n%2lu %2lu\n", totalp, totalk);
    t = time(NULL);
    for (totalp=0;totalp<400000L;totalp++)
        {
        ruby_crypt(plain, key, plain);
        }
    t = time(NULL) - t;
    if (t==0)
        t=1;
    fprintf(f,"%ld bytes encrypted per second.\n\n", (8*totalp)/(t));
    fclose(f);
    printf("%ld bytes encrypted per second.\n\n", (8*totalp)/(t));
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
    if (validate_file) testit();
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
            p = getenv("RLOCK_KEY");
            if (p)
                {
                strcpy((char *) passphrase, p);
                keysize = strlen((char *)passphrase);
                if (verbose)
                    puts("Using pass phrase from RLOCK_KEY environment variable.");
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
        if (keysize < 6)
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

