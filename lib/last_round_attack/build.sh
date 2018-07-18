#!/bin/sh

$1gcc -c -I./ -I../libflush -L../libflush/build/${SCA_TARGET_ARCH}/release last_round_attack.c -lflush
$1ar rscv liblast_round_attack.a last_round_attack.o
