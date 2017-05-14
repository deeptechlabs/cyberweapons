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
 * @file        Options.h
 * @author      offa
 *
 * Provides types and functions for options and settings.
 */

#ifndef OPTIONS_H
#define	OPTIONS_H

#include <getopt.h>
#include <stdbool.h>

#include "keygen/KeyGen.h"


#ifdef	__cplusplus
extern "C"
{
#endif

#define OPT_ASCII               'a' ///< Ascii format
#define OPT_ASCII_BLANKS        'w' ///< Ascii format including blanks
#define OPT_ASCII_REDUCED       'r' ///< Ascii reduced
#define OPT_ALPHANUMERIC        'p' ///< Alphanumeric
#define OPT_LENGTH              'l' ///< Keylength
#define OPT_SHORT               's' ///< Reduced output
#define OPT_HELP                'h' ///< Print help
#define OPT_VERSION             'v' ///< Print version

#define OPT_L_ASCII             "ascii"     ///< Ascii format
#define OPT_L_ASCII_BLANKS      "ascii-blank"   ///< Ascii format including blanks
#define OPT_L_ASCII_REDUCED     "ascii-reduced" ///< Ascii reduced
#define OPT_L_ALPHANUMERIC      "alphanum"  ///< Alphanumeric
#define OPT_L_LENGTH            "length"    ///< Keylength
#define OPT_L_SHORT             "short"     ///< Reduced output
#define OPT_L_HELP              "help"      ///< Print help
#define OPT_L_VERSION           "version"   ///< Print version


    /**
     * Options holding the parsed arguments.
     */
    struct CLOptions
    {
        bool valid;     ///< Indicates whether the options are valid or not
        bool exit;      ///< Exit after parsing
        bool shortOutput;   ///< Reduced output (generated key only)
        bool showHelp;  ///< Print the help
        bool showVersion;   ///< Print the version
        long keyLength;      ///< Keylength
        enum Format keyFormat;  ///< Key format
    };



    /**
     * Parses the command line arguments into a options struct.
     *
     * @param argc      Argument count
     * @param argv      Argument vector
     * @return          Parsed options
     */
    struct CLOptions parseOptions(int argc, char** argv);


#ifdef	__cplusplus
}
#endif

#endif	/* CLOPTIONS_H */

