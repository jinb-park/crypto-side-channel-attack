# Define armv8 flags

CC = ${SCA_CROSS_COMPILER}gcc
CFLAGS += -march=armv8-a -fPIE
LDFLAGS += -fPIE
