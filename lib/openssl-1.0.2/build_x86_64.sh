#!/bin/sh

./Configure shared -no-asm -no-hw -no-rc4 --prefix=/tmp/openssl --openssldir=/tmp/openssl
make CC=$1gcc RANLIB=$1ranlib LD=$1ld MAKEDEPPROG=$1gcc
