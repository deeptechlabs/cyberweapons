#!/bin/bash

set -ex


## Install CppUTest
CPPUTEST_VERSION=3.8
CPPUTEST=cpputest-${CPPUTEST_VERSION}

BUILD_FLAGS="-DC++11=OFF -DTESTS=OFF"

if [[ "$CXX" == clang* ]]; then
    BUILD_FLAGS="$BUILD_FLAGS -DCMAKE_CXX_FLAGS=-stdlib=libc++" 
fi

wget https://github.com/cpputest/cpputest/releases/download/v${CPPUTEST_VERSION}/${CPPUTEST}.tar.gz
tar -xzf ${CPPUTEST}.tar.gz
pushd ${CPPUTEST}
mkdir _build && cd _build
cmake $BUILD_FLAGS ..
make -j4 && sudo make install
popd

