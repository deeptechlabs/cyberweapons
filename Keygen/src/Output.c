/*
 * KeyGen is a key- and password generator.
 * Copyright (C) 2014-2017  offa
 *
 * This file is part of KeyGen.
 *
 * KeyGen is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * KeyGen is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with KeyGen.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file        KGOutput.c
 * @author      offa
 */

#include "keygen/Output.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/**
 * Prints a line of <code>lc</code> characters with the length
 * <code>length</code>. If <code>newLine</code> is set to <tt>true</tt> a new
 * line (<code>\n</code>) is appended.
 *
 * @param lc        Character
 * @param length    Length
 * @param newLine   If <tt>true</tt> a new line is appended, if <tt>false</tt>
 *                  there's no linebreak added
 */
static inline void printLine(char lc, unsigned int length, bool newLine)
{
    for( unsigned int i=0; i<length; ++i )
    {
        printf("%c", lc);
    }

    if( newLine == true )
    {
        printf("\n");
    }
}

/**
 * Prints a help for the command line argument.
 *
 * @param optLong       Long argument
 * @param optShort      Short argument
 * @param value         Value description if the arguments requires anargument,
 *                      if <tt>NULL</tt>, the argument has no parameter
 * @param text          Help text
 */
static inline void printHelpOption(const char* optLong, char optShort, const char* value, const char* text)
{
    if( value != NULL )
    {
        printf("  --%s <%s>\t-%c <%s>", optLong, value, optShort, value);
    }
    else
    {
        printf("  --%s\t-%c", optLong, optShort);
    }

    printf(" :  %s\n", text);
}

/**
 * Prints a common head.
 */
static inline void printHead()
{
    const int n = printf(" KeyGen\tv" KEYGEN_VERSION "\n");
    printLine('-', n, true);
}

void printHelp()
{
    printHead();
    printf("\nGenerates key's and passwords.\n");
    printf("\n Usage: keygen [Options]\n\n");

    printHelpOption(OPT_L_ASCII, OPT_ASCII, NULL, "Generates a key of ASCII characters, ranging from '!'\n\t\t\tto'~' (default)");
    printHelpOption(OPT_L_ASCII_BLANKS, OPT_ASCII_BLANKS, NULL, "Generates a key of ASCII characters, ranging from ' '\n\t\t\tto'~'; same as --ascii, but includes blanks");
    printHelpOption(OPT_L_ASCII_REDUCED, OPT_ASCII_REDUCED, NULL, "Generates a key of reduced ASCII");
    printHelpOption(OPT_L_ALPHANUMERIC, OPT_ALPHANUMERIC, NULL, "Generates a key of alphanumeric characters");
    printHelpOption(OPT_L_LENGTH, OPT_LENGTH, "n", "Generates a key of <n> bytes length");
    printHelpOption(OPT_L_SHORT, OPT_SHORT, NULL, "Shows only the key");
    printHelpOption(OPT_L_HELP, OPT_HELP, NULL, "Shows the help");
    printHelpOption(OPT_L_VERSION, OPT_VERSION, NULL, "Shows version informations and license.");
}

void printKey(const uint8_t* key, struct CLOptions options)
{
    if( options.shortOutput == true )
    {
        printf("%s\n", key);
        fflush(stdout);
    }
    else
    {
        printf("\n  Generated key:\n");
        printLine('-', 10, true);
        printf("%s\n", key);
        fflush(stdout);
        printLine('-', 10, true);
        printf("  Length : %ld / %ld\n\n", (long) strlen((char*) key), options.keyLength);
    }
}

void printVersion()
{
    printHead();
    printf("\n License :   GNU General Public License (GPL)\n");
    printf("   Keygen is program to generate key's and passwords."
    "\n   Copyright (C) 2014-2016  offa"
    "\n"
    "\n   This program is free software: you can redistribute it and/or modify"
    "\n   it under the terms of the GNU General Public License as published by"
    "\n   the Free Software Foundation, either version 3 of the License, or"
    "\n   (at your option) any later version."
    "\n"
    "\n   This program is distributed in the hope that it will be useful,"
    "\n   but WITHOUT ANY WARRANTY; without even the implied warranty of"
    "\n   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the"
    "\n   GNU General Public License for more details."
    "\n"
    "\n   You should have received a copy of the GNU General Public License"
    "\n   along with this program.  If not, see <http://www.gnu.org/licenses/>."
    "\n\n");
}


int generateKey(const struct CLOptions options)
{
    const long length = options.keyLength;

    if( length < KEY_MIN_LENGTH )
    {
        fprintf(stderr, "A keylength of %ld is to short! A minimum length of %d is required!\n", length, KEY_MIN_LENGTH);

        return KG_RTN_ERR_KEY_TO_SHORT;
    }

    uint8_t* buffer = malloc(length * sizeof(uint8_t) + 1);
    memset(buffer, 0, length+1);

    KeyGenError err = keygen_createKey(buffer, length, options.keyFormat);

    if( err == KG_ERR_SUCCESS )
    {
        buffer[length] = '\0';
        printKey(buffer, options);
    }
    else
    {
        fprintf(stderr, "ERROR : %d\n", err);

        return KG_RTN_ERR_ERROR;
    }

    keygen_cleanBuffer(buffer, length+1);
    free(buffer);

    return EXIT_SUCCESS;
}

const char* errorMessage(KeyGenError error)
{
    switch(error)
    {
        case KG_ERR_SUCCESS:
            return "";
        case KG_ERR_GENERAL:
            return "General error";
        case KG_ERR_MEMORY:
            return "Memory error";
        case KG_ERR_ILL_ARGUMENT:
            return "Illegal argument error";
        case KG_ERR_SECURITY:
            return "Security error";
        case KG_ERR_UNKNOWN:
        default:
            return "Unknown";
    }
}
