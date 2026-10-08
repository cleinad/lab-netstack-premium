# Compiler and Flags
CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2

TARGET := test_device

target: tests/test_device.o src/device.o
	$(CC) $(CFLAGS) -c $< -o $@