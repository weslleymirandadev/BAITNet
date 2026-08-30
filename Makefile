# IPv69 - build (C, static libc)
CC      := gcc
CFLAGS  := -Wall -Wextra -O2 -static -Iinclude -Ilib/ed25519/include
BUILD   := build

all: af69_test

$(BUILD):
	mkdir -p $(BUILD)

# drop the sudo requirement: give CAP_NET_RAW to the binaries (once per build)
caps: af69_test
	sudo setcap cap_net_raw+ep $(BUILD)/af69_test

# AF_69: kernel module + userspace test
AF69_KDIR ?= $(HOME)/wsl-kernel

# ed25519: standalone crypto library (also usable by the future stream
# transport / "own HTTPS" - see lib/ed25519/include/ed25519.h)
ED25519 := lib/ed25519/src/ed25519.c lib/ed25519/src/tweetnacl.c lib/ed25519/src/randombytes.c

af69:
	$(MAKE) -C kernel/af69 KDIR=$(AF69_KDIR)

af69_test: tests/af69_test.c src/IPv69/parse.c $(ED25519) include/IPv69/af69.h include/IPv69/parse.h include/IPv69/header.h lib/ed25519/include/ed25519.h | $(BUILD)
	$(CC) $(CFLAGS) -o $(BUILD)/$@ tests/af69_test.c src/IPv69/parse.c $(ED25519)

af69d: src/IPv69/af69d.c src/IPv69/parse.c $(ED25519) include/IPv69/af69.h include/IPv69/parse.h include/IPv69/header.h lib/ed25519/include/ed25519.h | $(BUILD)
	$(CC) $(CFLAGS) -o $(BUILD)/$@ src/IPv69/af69d.c src/IPv69/parse.c $(ED25519)

af69_raw: tests/af69_raw.c src/IPv69/parse.c $(ED25519) include/IPv69/af69.h include/IPv69/parse.h include/IPv69/header.h lib/ed25519/include/ed25519.h | $(BUILD)
	$(CC) $(CFLAGS) -o $(BUILD)/$@ tests/af69_raw.c src/IPv69/parse.c $(ED25519)

ipv69-keygen: src/IPv69/ipv69-keygen.c $(ED25519) lib/ed25519/include/ed25519.h | $(BUILD)
	$(CC) $(CFLAGS) -o $(BUILD)/$@ src/IPv69/ipv69-keygen.c $(ED25519)

ip69d: src/IPv69/ip69d.c src/IPv69/parse.c $(ED25519) include/IPv69/af69.h include/IPv69/parse.h include/IPv69/header.h lib/ed25519/include/ed25519.h | $(BUILD)
	$(CC) $(CFLAGS) -o $(BUILD)/$@ src/IPv69/ip69d.c src/IPv69/parse.c $(ED25519)

ip69: src/IPv69/ip69.c | $(BUILD)
	$(CC) $(CFLAGS) -o $(BUILD)/$@ src/IPv69/ip69.c

.PHONY: all caps af69 af69_test af69d af69_raw ip69d ip69 ipv69-keygen
