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

#include "keygen/KeyGen.h"
#include "TestUtil.h"
#include <string.h>
#include <CppUTest/TestHarness.h>

TEST_GROUP(MemoryTest)
{
};

TEST(MemoryTest, testCleanUp)
{
    const size_t size = 1000 * sizeof(uint8_t);
    uint8_t* buffer = allocate(size);
    uint8_t expected[size];
    memset(expected, 0, size);

    KeyGenError rtn = keygen_createKey(buffer, size, ASCII);
    CHECK_EQUAL(KG_ERR_SUCCESS, rtn);

    keygen_cleanBuffer(buffer, size);
    MEMCMP_EQUAL(expected, buffer, size);

    free(buffer);
}

TEST(MemoryTest, cleanUpBorderCheck)
{
    const size_t size = 1000 * sizeof(uint8_t);
    const size_t allocSize = size + 4;
    uint8_t* allocBuffer = allocate(allocSize);
    uint8_t* buffer = allocBuffer + 2;
    uint8_t expected[allocSize];

    memset(expected, 0, allocSize);
    expected[0] = 0xCA;
    expected[1] = 0xFE;
    expected[allocSize - 2] = 0xCA;
    expected[allocSize - 1] = 0xFE;

    KeyGenError rtn = keygen_createKey(buffer, size, ASCII);
    CHECK_EQUAL(KG_ERR_SUCCESS, rtn);

    keygen_cleanBuffer(buffer, size);
    MEMCMP_EQUAL(expected + 2, buffer, size);
    CHECK_EQUAL(0xCA, expected[0]);
    CHECK_EQUAL(0xFE, expected[1]);
    CHECK_EQUAL(0xCA, expected[allocSize - 2]);
    CHECK_EQUAL(0xFE, expected[allocSize - 1]);

    free(allocBuffer);
}

TEST(MemoryTest, overlength)
{
    const size_t overLength =  1000000 * sizeof(uint8_t);

    uint8_t* buffer = allocate(overLength * sizeof(uint8_t));
    KeyGenError rtn = keygen_createKey(buffer, overLength, ASCII);
    CHECK_EQUAL(KG_ERR_SUCCESS, rtn);

    keygen_cleanAndFreeBuffer(buffer, overLength);
}

TEST(MemoryTest, overAndUnderflow)
{
    const size_t size = 1000 * sizeof(uint8_t);
    const size_t allocSize = size + 4;
    uint8_t* allocBuffer = allocate(allocSize);
    uint8_t* buffer = allocBuffer + 2;

    allocBuffer[0] = 0xCA;
    allocBuffer[1] = 0xFE;
    allocBuffer[allocSize - 2] = 0xCA;
    allocBuffer[allocSize - 1] = 0xFE;

    KeyGenError rtn = keygen_createKey(buffer, size, ASCII);
    CHECK_EQUAL(KG_ERR_SUCCESS, rtn);

    CHECK_EQUAL(0xCA, allocBuffer[0]);
    CHECK_EQUAL(0XFE, allocBuffer[1]);
    CHECK_EQUAL(0xCA, allocBuffer[allocSize - 2]);
    CHECK_EQUAL(0xFE, allocBuffer[allocSize - 1]);

    keygen_cleanBuffer(buffer, size);

    CHECK_EQUAL(0xCA, allocBuffer[0]);
    CHECK_EQUAL(0XFE, allocBuffer[1]);
    CHECK_EQUAL(0xCA, allocBuffer[allocSize - 2]);
    CHECK_EQUAL(0xFE, allocBuffer[allocSize - 1]);

    free(allocBuffer);
}

