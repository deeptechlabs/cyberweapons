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

#include <CppUTest/TestHarness.h>
#include "keygen/KeyGen.h"
#include <string.h>

extern const char ALPHANUMERIC_CHARS[];
extern const size_t ALPHANUMERIC_LENGTH;
extern const char ASCII_REDUCED_CHARS[];
extern const size_t ASCII_REDUCED_LENGTH;
extern const char ASCII_BLANK_CHARS[];
extern const size_t ASCII_BLANK_LENGTH;
extern const char ASCII_CHARS[];
extern const size_t ASCII_LENGTH;

TEST_GROUP(DataTest)
{
};

TEST(DataTest, formatCharsLength)
{
    CHECK_EQUAL(94u, ASCII_LENGTH);
    CHECK_EQUAL(95u, ASCII_BLANK_LENGTH);
    CHECK_EQUAL(88u, ASCII_REDUCED_LENGTH);
    CHECK_EQUAL(62u, ALPHANUMERIC_LENGTH);
}

TEST(DataTest, formatChars)
{
    const char* charsAsciiReduced = "!#$%&()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]_abcdefghijklmnopqrstuvwxyz{}~";
    const char* charsAsciiBlanks = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
    const char* charsAscii = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
    const char* charsAlphaNum = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    MEMCMP_EQUAL(charsAscii, ASCII_CHARS, ASCII_LENGTH);
    MEMCMP_EQUAL(charsAsciiBlanks, ASCII_BLANK_CHARS, ASCII_BLANK_LENGTH);
    MEMCMP_EQUAL(charsAsciiReduced, ASCII_REDUCED_CHARS, ASCII_REDUCED_LENGTH);
    MEMCMP_EQUAL(charsAlphaNum, ALPHANUMERIC_CHARS, ALPHANUMERIC_LENGTH);
}
