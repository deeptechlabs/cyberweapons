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
 * @file        Output.h
 * @author      offa
 *
 * Contains functions to show informations and other output.
 */

#ifndef OUTPUT_H
#define OUTPUT_H

#include "keygen/Options.h"
#include "keygen/KeyGen.h"


#ifdef  __cplusplus
extern "C"
{
#endif

    enum
    {
        KG_RTN_ERR_ERROR = 1,       ///< General error.
        KG_RTN_ERR_KEY_TO_SHORT = 2 ///< Error indicating a to short key.
    };



    /**
     * Shows help information.
     */
    void printHelp();

    /**
     * Prints the key with the given options.
     *
     * @param key       Key
     * @param options   Options to use for printing
     */
    void printKey(const uint8_t* key, struct CLOptions options);

    /**
     * Shows version informations and license.
     */
    void printVersion();

    /**
     * Generates and prints a key according the parameters in
     * <code>options</code>.
     *
     * @remark
     * A key less than <code>KEY_LENGTH_MIN</code> is not supported and results
     * in an error.
     *
     * @param options       Options
     * @return              Returns <code>EXIT_SUCCESS</code> <code>(0)</code>
     *                      on a clean exit or an error code in case of an error
     */
    int generateKey(const struct CLOptions options);


    /**
     * Returns an error message for the error code.
     *
     * @param error     Error code
     * @return          Error message
     */
    const char* errorMessage(KeyGenError error);

#ifdef  __cplusplus
}
#endif

#endif  /* CLOUTPUT_H */

