#!/bin/sh

export SCA_TARGET_ARCH=armv8
export SCA_CROSS_COMPILER=aarch64-linux-gnu-

rm -rf build
mkdir -p build/lib/
mkdir -p build/aes-attack/one-round-attack/real-security-daemon/
mkdir -p build/aes-attack/last-round-attack/real-security-daemon/

# build libraries
cd lib/openssl-1.0.2
./build_armv8.sh ${SCA_CROSS_COMPILER}
cp -f libcrypto.so.1.0.0 ../../build/lib/

cd ../libflush
make ARCH=${SCA_TARGET_ARCH}
cp -f build/${SCA_TARGET_ARCH}/release/libflush.a ../../build/lib/

cd ../one_round_attack
./build.sh ${SCA_CROSS_COMPILER}
cp -f libone_round_attack.a ../../build/lib/

cd ../last_round_attack
./build.sh ${SCA_CROSS_COMPILER}
cp -f liblast_round_attack.a ../../build/lib/

# build security daemon for one-round-attack
cd ../../
cd aes-attack/one-round-attack/real-security-daemon
./build.sh ${SCA_CROSS_COMPILER}
cp -f attacker ../../../build/aes-attack/one-round-attack/real-security-daemon/
cp -f security_daemon ../../../build/aes-attack/one-round-attack/real-security-daemon/
cp -f plain.txt ../../../build/aes-attack/one-round-attack/real-security-daemon/

# build security daemon for last-round-attack
cd ../../last-round-attack/real-security-daemon
./build.sh ${SCA_CROSS_COMPILER}
cp -f attacker ../../../build/aes-attack/last-round-attack/real-security-daemon/
cp -f security_daemon ../../../build/aes-attack/last-round-attack/real-security-daemon/
cp -f plain.txt ../../../build/aes-attack/last-round-attack/real-security-daemon/

