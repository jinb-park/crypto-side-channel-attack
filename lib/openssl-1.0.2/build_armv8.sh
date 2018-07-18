#!/bin/sh

./Configure linux-generic64 shared -DL_ENDIAN --prefix=/tmp/openssl --openssldir=/tmp/openssl
make CC=$1gcc RANLIB=$1ranlib LD=$1ld MAKEDEPPROG=$1gcc PROCESSOR=ARM
