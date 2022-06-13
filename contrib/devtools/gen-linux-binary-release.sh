#!/bin/bash
# Copyright (c) 2016-2021 The Hush developers
# Released under the GPLv3

set -e
set -x

#hardcode and uncomment if hushd is not running on this machine
#VERSION=3.6.3
VERSION=$(./src/hushd --version|grep version|cut -d' ' -f4|cut -d- -f1|sed 's/v//g')
FILE="hush-$VERSION-linux-amd64.tar"
TIME=$(perl -e 'print time')

mv build build.$TIME
mkdir build
cp contrib/asmap/asmap.dat build/
cp sapling*.params build/
cd src
cp hushd hush-cli hush-tx hush-smart-chain ../build
cd ../build
strip hushd hush-cli hush-tx
tar -f $FILE -c  *
gzip -9 $FILE
sha256sum *.gz
du -sh *.gz
