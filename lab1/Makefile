# Compiler and warning settings used when compiling each source file.
CC ?= cc
CPPFLAGS ?= -Isrc
CFLAGS ?= -Wall -Wextra -Wpedantic -g
LDLIBS ?= -lpcap

SOURCES := src/device.c src/packetio.c
OBJECTS := $(SOURCES:.c=.o)

.PHONY: objects test_packetio

# Compile the link-layer implementation without linking or running a program.
objects: $(OBJECTS)

# Link a small program that sends one identifiable Ethernet frame.
test_packetio: tests/test_packetio.o $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

# Build the matching object file for any C source file.
%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
