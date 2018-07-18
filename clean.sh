#!/bin/sh

rm -rf build

# clean libraries
cd lib/openssl-1.0.2
./clean.sh

cd ../libflush
rm -rf build/

cd ../one_round_attack
./clean.sh

cd ../last_round_attack
./clean.sh

# clean attacks
cd ../../
cd aes-attack/one-round-attack/real-security-daemon
./clean.sh

cd ../../last-round-attack/real-security-daemon
./clean.sh
cd ../../../

