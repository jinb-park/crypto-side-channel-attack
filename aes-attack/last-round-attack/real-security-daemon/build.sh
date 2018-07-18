#!/bin/sh

# target => openssl
$1gcc -I./ -I../../../lib/openssl-1.0.2/include -L../../../lib/openssl-1.0.2 -o security_daemon security_daemon.c -lcrypto -lrt
$1gcc -I./ -I../../../lib/last_round_attack -I../../../lib/libflush -L../../../lib/last_round_attack -L../../../lib/libflush/build/${SCA_TARGET_ARCH}/release -o attacker attacker.c -lrt -llast_round_attack -lflush

