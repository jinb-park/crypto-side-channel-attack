#!/bin/sh

$1gcc -c -I./ -I../libflush -L../libflush/build/${SCA_TARGET_ARCH}/release one_round_attack.c -lflush
$1ar rscv libone_round_attack.a one_round_attack.o
