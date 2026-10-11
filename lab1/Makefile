# Compiler and warning settings used when compiling each source file.
CC ?= cc
CPPFLAGS ?= -Isrc
CFLAGS ?= -Wall -Wextra -Wpedantic -g
LDLIBS ?= -lpcap
THREAD_FLAGS ?= -pthread

SOURCES := src/device.c src/packetio.c
OBJECTS := $(SOURCES:.c=.o)

.PHONY: objects test_device test_packetio

# Compile the link-layer implementation without linking or running a program.
objects: $(OBJECTS)

# List interfaces and verify device registration behavior.
test_device: tests/test_device.o src/device.o
	$(CC) $(LDFLAGS) $(THREAD_FLAGS) -o $@ $^ $(LDLIBS)

# Link a small program that sends one identifiable Ethernet frame.
test_packetio: tests/test_packetio.o $(OBJECTS)
	$(CC) $(LDFLAGS) $(THREAD_FLAGS) -o $@ $^ $(LDLIBS)

# Build the matching object file for any C source file.
%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(THREAD_FLAGS) -c $< -o $@
