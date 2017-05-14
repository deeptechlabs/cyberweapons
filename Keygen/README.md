# [KeyGen](https://github.com/offa/keygen)

[![Build Status](https://travis-ci.org/offa/keygen.svg?branch=master)](https://travis-ci.org/offa/keygen)
[![GitHub release](https://img.shields.io/github/release/offa/keygen.svg)](https://github.com/offa/keygen/releases)
[![License](https://img.shields.io/badge/license-GPLv3-yellow.svg)](LICENSE)
![C](https://img.shields.io/badge/c-11-green.svg)

KeyGen is a generator for keys and passwords. It's usable as standalone application and library.

The cryptography behind is provided by *OpenSSL*.

## Requirements

 - [**OpenSSL**](https://www.openssl.org/)
 - [**CMake**](http://www.cmake.org/)
 - [**Doxygen**](http://doxygen.nl/) — *(Optional)*
 - [**CppUTest**](https://github.com/cpputest/cpputest) — *(Optional; requires C++ Compiler)*

## Building

Building the library and application:

    mkdir build
    cmake ..
    make

Furthermore there are build targets either application or library. Run `make <Target>` to build them.

## Testing

After building, the tests are executed within the build directory using:

    ctest

or running `make` with one of these targets:

make        | < target >
----------- | -------------------------------
`test`      | Runs ctest (same as `ctest`)
`unittest`  | Builds and  runs all test
`coverage`  | Coverage (requires lcov)

## Usage

The unit of length are (ascii-) characters (1 char = 1 byte). So a length of 20 means 20 (ascii-) char's = 20 Byte.

### Application

The application is used with commandline arguments. Run `keygen -h` to print the help.

#### Arguments:

```
 Usage: keygen [Options]

  --ascii	-a :  Generates a key of ASCII characters, ranging from '!' to'~' (default)
  --ascii-blank	-w :  Generates a key of ASCII characters, ranging from ' ' to'~';
                      same as --ascii, but includes blanks
  --ascii-reduced	-r :  Generates a key of reduced ASCII
  --alphanum	-p :  Generates a key of alphanumeric characters
  --length <n>	-l <n> :  Generates a key of <n> bytes length
  --short	-s :  Shows only the key
  --help	-h :  Shows the help
  --version	-v :  Shows version informations and license.
```

**Note:** For generating, the `--length` / `-l` parameter is *always* necessary.
 
#### Examples

Key of 24 length:

    $ keygen -l 20

      Generated key:
    ----------
    amZ5QiX>9Z-=4U.XP;bD
    ----------
      Length : 20 / 20

this is equal to `keygen --ascii -l 20` and `keygen -a -l 20`.

The same key size, but with short (key only) output:

    $ keygen -s -l 20
    ZI^fD{dX<qa?uw?%'acM


Key of 4048 length, stored in a file:

    $ keygen --short --length 4048 > example.key

*(Use `--short` / `-s` to write key only)*


### Library

```c
const int KEY_LENGTH = 100000; // Key length
uint8_t* buffer = malloc(KEY_LENGTH * sizeof(uint8_t)); // allocate buffer

if( buffer == NULL )
{
    // Error - malloc() failed
}
else
{
    KeyGenError err = keygen_createKey(buffer, KEY_LENGTH, ASCII);

    if( err == KG_ERR_SUCCESS )
    {
        // Key generated, do something
    }
    else
    {
        // Error - handle that case
    }

    // Finally clean and free the buffer
    keygen_cleanAndFreeBuffer(buffer, length);
}
```

## Notes

 - The keylength is set to a minimum of 8 - lesser length is not allowed
 - Using parameter `-s` / `--short` will reduce the output to key only

## Documentation

 - [OpenSSL](https://www.openssl.org/)
 - [OpenSSL Wiki](http://wiki.openssl.org/index.php/Main_Page)

## License

**GNU General Public License (GPL)**

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
