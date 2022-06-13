#!/bin/bash
# Copyright (c) 2016-2021 The Hush developers
# Distributed under the GPLv3 software license, see the accompanying
# file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html
export HOST=x86_64-w64-mingw32
CXX=x86_64-w64-mingw32-g++-posix
CC=x86_64-w64-mingw32-gcc-posix
PREFIX="$(pwd)/depends/$HOST"

set -eu -o pipefail

set -x
cd "$(dirname "$(readlink -f "$0")")/.."

cd depends/ && make HOST=$HOST V=1 NO_QT=1
cd ../
WD=$PWD
cd src/cc
echo $PWD
./makecustom
cd $WD

./autogen.sh
CONFIG_SITE=$PWD/depends/x86_64-w64-mingw32/share/config.site CXXFLAGS="-DPTW32_STATIC_LIB -DCURL_STATICLIB -fopenmp -pthread" ./configure --prefix="${PREFIX}" --host=x86_64-w64-mingw32 --enable-static --disable-shared
sed -i 's/-lboost_system-mt /-lboost_system-mt-s /' configure
cd src/
CC="${CC} -g " CXX="${CXX} -g " make V=1  hushd.exe hush-cli.exe hush-tx.exe
