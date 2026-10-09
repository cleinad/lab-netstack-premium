# Compiler and warning settings used when compiling each source file.
CC ?= cc
CPPFLAGS ?= -Isrc
CFLAGS ?= -Wall -Wextra -Wpedantic -g

SOURCES := src/device.c src/packetio.c
OBJECTS := $(SOURCES:.c=.o)

.PHONY: objects

# Compile the link-layer implementation without linking or running a program.
objects: $(OBJECTS)

# Build the matching object file for any C source file.
%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
