#!/bin/bash
# Copyright (c) 2016-2021 The Hush developers
# Distributed under the GPLv3 software license, see the accompanying
# file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html
# OPEN BOUNTY
# Send your CPU and RAM and time it takes to sync a HUSH full node for
# 5 HUSH as thanks for decentralized performance testing
git clone https://git.hush.is/hush/hush3
cd hush3
# Build with 2 cores
# You need 2GB of RAM per core, don't use too many
# (GB of RAM)/2 - 1 is the optimal core count for compiling Hush
# `nproc` tells you how many cores you have
JOBS=2
# Want to fix this parrallel-only build system bug we inherited ? you are a new hush dev
./build.sh -j$JOBS;make -j$JOBS;make -j$JOBS;make -j$JOBS
./src/hushd &> hush.log &
# You can give the entire or parts of this file to Hush developers for debugging,
# but there is a lot of metadata!!! We don't want any more than we need to fix bugz
tail -f hush.log
