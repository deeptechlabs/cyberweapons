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
 * @file        Main.c
 * @author      offa
 *
 * Contains the <code>main()</code> function.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include "keygen/Options.h"
#include "keygen/Output.h"



/**
 * The <code>main</code> function of the program.
 *
 * @param argc      Argument count
 * @param argv      Argument vector
 * @return          Returns <code>EXIT_SUCCESS</code> <code>(0)</code> on a
 *                  clean exit or an error code in case of an error
 */
int main(int argc, char** argv)
{
    struct CLOptions options = parseOptions(argc, argv);

    if( ( options.showHelp == true && options.exit == true ) )
    {
        printHelp();
    }
    else if( options.valid == true )
    {
        if( options.showVersion == true )
        {
            printVersion();
        }
        else
        {
            const int rtn = generateKey(options);

            if( rtn != EXIT_SUCCESS )
            {
                return rtn;
            }
        }
    }
    else
    {
        /* empty */
    }

    return EXIT_SUCCESS;
}
