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
 * @file        KGOptions.c
 * @author      offa
 */

#include "keygen/Options.h"
#include <stdio.h>
#include <stdlib.h>

/** Minimum of arguments. */
#define OPT_MIN_ARGS            2
/** Getopt string. */
#define GETOPT_CLI_STR          "sawrpl:hv"


static const struct option getoptOptions[] =
{
    { OPT_L_ASCII, no_argument, 0, OPT_ASCII },
    { OPT_L_ASCII_REDUCED, no_argument, 0, OPT_ASCII_REDUCED },
    { OPT_L_ASCII_BLANKS, no_argument, 0, OPT_ASCII_BLANKS },
    { OPT_L_ALPHANUMERIC, no_argument, 0, OPT_ALPHANUMERIC },
    { OPT_L_LENGTH, required_argument, 0, OPT_LENGTH },
    { OPT_L_SHORT, no_argument, 0, OPT_SHORT },
    { OPT_L_HELP, no_argument, 0, OPT_HELP },
    { OPT_L_VERSION, no_argument, 0, OPT_VERSION },
    { NULL, 0, 0, 0 }
};


struct CLOptions parseOptions(int argc, char** argv)
{
    struct CLOptions options =
    {
        .valid = true,
        .exit = false,
        .shortOutput = false,
        .showHelp = false,
        .showVersion = false,
        .keyLength = -1,
        .keyFormat = ASCII
    };


    if( argc < OPT_MIN_ARGS )
    {
        options.valid = true;
        options.exit = true;
        options.showHelp = true;
    }
    else
    {
        int c;
        int optionIndex;

        while( ( c = getopt_long(argc, argv, GETOPT_CLI_STR, getoptOptions, &optionIndex) ) != -1 )
        {
            switch( c )
            {
                case OPT_ASCII:
                    options.keyFormat = ASCII;
                    options.valid &= true;
                    break;
                case OPT_ASCII_BLANKS:
                    options.keyFormat = ASCII_BLANKS;
                    options.valid &= true;
                    break;
                case OPT_ASCII_REDUCED:
                    options.keyFormat = ASCII_REDUCED;
                    options.valid &= true;
                    break;
                case OPT_ALPHANUMERIC:
                    options.keyFormat = ALPHA_NUMERIC;
                    options.valid &= true;
                    break;
                case OPT_LENGTH:
                {
                    options.keyLength = strtol(optarg, (char**) NULL, 10);
                    options.valid &= true;
                }
                    break;
                case OPT_SHORT:
                    options.shortOutput = true;
                    options.valid &= true;
                    break;
                case OPT_HELP:
                    options.showHelp = true;
                    options.valid &= true;
                    options.exit = true;
                    break;
                case OPT_VERSION:
                    options.showVersion = true;
                    options.valid &= true;
                    options.exit = true;
                    break;
                default:
                    options.exit = true;
                    options.valid = false;
                    options.showHelp = false;
                    break;
            }

            if( options.exit == true || options.valid == false )
            {
                break;
            }
        }

        if ( optind < argc )
        {
            fprintf(stderr, "Not an option: %s\n", argv[optind]);
            options.exit = true;
            options.valid = false;
        }
    }

    return options;
}
