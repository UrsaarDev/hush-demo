#!/usr/bin/env bash
# Copyright (c) 2016-2021 The Hush developers
# Distributed under the GPLv3 software license, see the accompanying
# file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html
# A wrapper around ./zcutil/build.sh for instrumenting the build with AFL:
#   ./zcutil/afl/afl-build.sh <directory where AFL is installed> <fuzz case>
# You may obtain a copy of AFL using ./zcutil/afl/afl-get.sh.

set -eu -o pipefail

export AFL_INSTALL_DIR=$(realpath "$1")
FUZZ_CASE="$2"
shift 2
export AFL_LOG_DIR="$(pwd)"
export ZCUTIL=$(realpath "./zcutil")

cp "./src/fuzzing/$FUZZ_CASE/fuzz.cpp" src/fuzz.cpp

CONFIGURE_FLAGS="--enable-tests=no --enable-fuzz-main" "$ZCUTIL/build.sh" "CC=$ZCUTIL/afl/hush-wrapper-gcc" "CXX=$ZCUTIL/afl/hush-wrapper-g++" AFL_HARDEN=1 "$@"

echo "You can now run AFL as follows:"
echo "$ ./zcutil/afl/afl-run.sh '$AFL_INSTALL_DIR' '$FUZZ_CASE'"
