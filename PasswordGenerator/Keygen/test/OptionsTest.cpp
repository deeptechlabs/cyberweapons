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
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "keygen/Options.h"

TEST_GROUP(OptionsTest)
{
    void setup()
    {
        optind = 0;

        fflush(stderr);
        origStdErr = dup(STDERR_FILENO);
        FILE* unused = freopen("NUL", "a", stderr);
        (void) unused;
    }

    void teardown()
    {
        fflush(stderr);
        dup2(origStdErr, STDERR_FILENO);
    }

    int origStdErr;
};
static char name[] = "OptionsTest";

TEST(OptionsTest, testNoArgsReturnsHelpAndExit)
{
    char* argv[] = {name};
    int argc = sizeof(argv) / sizeof(char*);

    struct CLOptions result = parseOptions(argc, argv);
    CHECK_EQUAL(true, result.valid);
    CHECK_EQUAL(true, result.showHelp);
    CHECK_EQUAL(true, result.exit);
}

TEST(OptionsTest, testFormatArgumentAscii)
{
    char param[] = "-a";
    char* argv[] = {name, param};
    int argc = sizeof(argv) / sizeof(char*);

    struct CLOptions result = parseOptions(argc, argv);

    CHECK_EQUAL(true, result.valid);
    CHECK_EQUAL(ASCII, result.keyFormat);
}

TEST(OptionsTest, testFormatArgumentAsciiLong)
{
    char param[] = "--ascii";
    char* argv[] = {name, param};
    int argc = sizeof(argv) / sizeof(char*);

    struct CLOptions result = parseOptions(argc, argv);

    CHECK_EQUAL(true, result.valid);
    CHECK_EQUAL(ASCII, result.keyFormat);
}

TEST(OptionsTest, testFormatArgumentAsciiReduced)
{
    char param[] = "-r";
    char* argv[] = {name, param};
    int argc = sizeof(argv) / sizeof(char*);

    struct CLOptions result = parseOptions(argc, argv);

    CHECK_EQUAL(true, result.valid);
    CHECK_EQUAL(ASCII_REDUCED, result.keyFormat);
}

TEST(OptionsTest, testFormatArgumentAsciiReducedLong)
{
    char param[] = "--ascii-reduced";
    char* argv[] = {name, param};
    int argc = sizeof(argv) / sizeof(char*);

    struct CLOptions result = parseOptions(argc, argv);

    CHECK_EQUAL(true, result.valid);
    CHECK_EQUAL(ASCII_REDUCED, result.keyFormat);
}

TEST(OptionsTest, testFormatArgumentAsciiBlank)
{
    char param[] = "-w";
    char* argv[] = {name, param};
    int argc = sizeof(argv) / sizeof(char*);

    struct CLOptions result = parseOptions(argc, argv);

    CHECK_EQUAL(true, result.valid);
    CHECK_EQUAL(ASCII_BLANKS, result.keyFormat);
}

TEST(OptionsTest, testFormatArgumentAsciiBlankLong)
{
    char param[] = "--ascii-blank";
    char* argv[] = {name, param};
    int argc = sizeof(argv) / sizeof(char*);

    struct CLOptions result = parseOptions(argc, argv);

    CHECK_EQUAL(true, result.valid);
    CHECK_EQUAL(ASCII_BLANKS, result.keyFormat);
}

TEST(OptionsTest, testFormatArgumentAlphaNumeric)
{
    char param[] = "-p";
    char* argv[] = {name, param};
    int argc = sizeof(argv) / sizeof(char*);

    struct CLOptions result = parseOptions(argc, argv);

    CHECK_EQUAL(true, result.valid);
    CHECK_EQUAL(ALPHA_NUMERIC, result.keyFormat);
}

TEST(OptionsTest, testFormatArgumentAlphaNumericLong)
{
    char param[] = "--alphanum";
    char* argv[] = {name, param};
    int argc = sizeof(argv) / sizeof(char*);

    struct CLOptions result = parseOptions(argc, argv);

    CHECK_EQUAL(true, result.valid);
    CHECK_EQUAL(ALPHA_NUMERIC, result.keyFormat);
}

TEST(OptionsTest, testLength)
{
    char param[] = "-l";
    char value[] = "10";
    char* argv[] = {name, param, value};
    int argc = sizeof(argv) / sizeof(char*);

    struct CLOptions result = parseOptions(argc, argv);

    CHECK_EQUAL(true, result.valid);
    CHECK_EQUAL(10, result.keyLength);
}

TEST(OptionsTest, testLengthLong)
{
    char param[] = "--length";
    char value[] = "10";
    char* argv[] = {name, param, value};
    int argc = sizeof(argv) / sizeof(char*);

    struct CLOptions result = parseOptions(argc, argv);

    CHECK_EQUAL(true, result.valid);
    CHECK_EQUAL(10, result.keyLength);
}

TEST(OptionsTest, testFormatArgumentShort)
{
    char param[] = "-s";
    char* argv[] = {name, param};
    int argc = sizeof(argv) / sizeof(char*);

    struct CLOptions result = parseOptions(argc, argv);

    CHECK_EQUAL(true, result.valid);
    CHECK_EQUAL(true, result.shortOutput);
}

TEST(OptionsTest, testFormatArgumentShortLong)
{
    char param[] = "--short";
    char* argv[] = {name, param};
    int argc = sizeof(argv) / sizeof(char*);

    struct CLOptions result = parseOptions(argc, argv);

    CHECK_EQUAL(true, result.valid);
    CHECK_EQUAL(true, result.shortOutput);
}

TEST(OptionsTest, testShowHelp)
{
    char param[] = "-h";
    char* argv[] = {name, param};
    int argc = sizeof(argv) / sizeof(char*);

    struct CLOptions result = parseOptions(argc, argv);

    CHECK_EQUAL(true, result.valid);
    CHECK_EQUAL(true, result.showHelp);
    CHECK_EQUAL(true, result.exit);
}

TEST(OptionsTest, testShowHelpLong)
{
    char param[] = "--help";
    char* argv[] = {name, param};
    int argc = sizeof(argv) / sizeof(char*);

    struct CLOptions result = parseOptions(argc, argv);

    CHECK_EQUAL(true, result.valid);
    CHECK_EQUAL(true, result.showHelp);
    CHECK_EQUAL(true, result.exit);
}

TEST(OptionsTest, testShowVersion)
{
    char param[] = "-v";
    char* argv[] = {name, param};
    int argc = sizeof(argv) / sizeof(char*);

    struct CLOptions result = parseOptions(argc, argv);

    CHECK_EQUAL(true, result.valid);
    CHECK_EQUAL(true, result.showVersion);
    CHECK_EQUAL(true, result.exit);
}

TEST(OptionsTest, testShowVersionLong)
{
    char param[] = "--version";
    char* argv[] = {name, param};
    int argc = sizeof(argv) / sizeof(char*);

    struct CLOptions result = parseOptions(argc, argv);

    CHECK_EQUAL(true, result.valid);
    CHECK_EQUAL(true, result.showVersion);
    CHECK_EQUAL(true, result.exit);
}

TEST(OptionsTest, testInvalidOptionSetsInvalidAndExit)
{
    char param[] = "-q";
    char* argv[] = {name, param};
    int argc = sizeof(argv) / sizeof(char*);

    struct CLOptions result = parseOptions(argc, argv);

    CHECK_EQUAL(false, result.valid);
    CHECK_EQUAL(true, result.exit);
}
