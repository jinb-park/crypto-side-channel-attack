# Define armv7 flags

CC = ${SCA_CROSS_COMPILER}gcc
CFLAGS += -march=armv7-a -fPIE
LDFLAGS += -fPIE
