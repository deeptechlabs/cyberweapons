cmake_minimum_required(VERSION 3.2)

project(keygen VERSION 0.3.3)

option(UNITTEST "Builds unit tests" ON)
option(UNITTEST_VERBOSE "Verbose unit test output" OFF)
option(COVERAGE "Enables source code coverage" OFF)
option(DOXYFILE "Generates the Doxyfile for Doxygen documentation" ON)

message(STATUS "~~ ${PROJECT_NAME} ${PROJECT_VERSION} ~~")

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include_directories("include")


find_package(PkgConfig REQUIRED)
pkg_search_module(OPENSSL REQUIRED openssl)

if( OPENSSL_FOUND )
    include_directories(SYSTEM ${OPENSSL_INCLUDE_DIRS})
    message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")
endif()

if( UNITTEST )
    enable_testing()
    subdirs(test)
endif()

include(Coverage)
include(Doxygen)
include(Memcheck)

add_definitions(-Wall
                -Wextra
                -Werror
                -pedantic
                -Wshadow
                )

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11")

subdirs(src)

