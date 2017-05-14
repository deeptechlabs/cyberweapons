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
#include <string.h>
#include "keygen/KeyGen.h"
#include "TestUtil.h"


TEST_GROUP(ArgumentTest)
{
    void teardown()
    {
        keygen_cleanAndFreeBuffer(buffer, size);
    }

    uint8_t* buffer;
    size_t size;
};

TEST(ArgumentTest, toShortLengthRejected)
{
    size = 7 * sizeof(uint8_t);
    buffer = allocate(size);

    KeyGenError rtn = keygen_createKey(buffer, size, ASCII);
    CHECK_EQUAL(KG_ERR_ILL_ARGUMENT, rtn);
}

TEST(ArgumentTest, toShortLengthDoesntChangeBuffer)
{
    size = 7 * sizeof(uint8_t);
    buffer = allocate(size);
    uint8_t* expected = allocate(size);

    memset(expected, 0, size);
    memset(buffer, 0, size);

    KeyGenError rtn = keygen_createKey(buffer, size, ASCII);
    CHECK_EQUAL(KG_ERR_ILL_ARGUMENT, rtn);
    MEMCMP_EQUAL(expected, buffer, size);

    free(expected);
}

TEST(ArgumentTest, allowedSizeGeneratesKey8Byte)
{
    size = 8 * sizeof(uint8_t);
    buffer = allocate(size);

    KeyGenError rtn = keygen_createKey(buffer, size, ASCII);
    CHECK_EQUAL(KG_ERR_SUCCESS, rtn);
}

TEST(ArgumentTest, allowedSizeGeneratesKey1200Byte)
{
    size = 1200 * sizeof(uint8_t);
    buffer = allocate(size);

    KeyGenError rtn = keygen_createKey(buffer, size, ASCII);
    CHECK_EQUAL(KG_ERR_SUCCESS, rtn);
}

