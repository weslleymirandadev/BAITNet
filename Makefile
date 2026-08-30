# IPv69 - build (C, static libc)
CC      := gcc
CFLAGS  := -Wall -Wextra -O2 -static -Iinclude
BUILD   := build

all: af69_test

$(BUILD):
	mkdir -p $(BUILD)

# drop the sudo requirement: give CAP_NET_RAW to the binaries (once per build)
caps: af69_test
	sudo setcap cap_net_raw+ep $(BUILD)/af69_test

# AF_69: kernel module + userspace test
AF69_KDIR ?= $(HOME)/wsl-kernel

CRYPTO := src/IPv69/tweetnacl.c src/IPv69/randombytes.c

af69:
	$(MAKE) -C kernel/af69 KDIR=$(AF69_KDIR)

af69_test: tests/af69_test.c src/IPv69/parse.c $(CRYPTO) include/IPv69/af69.h include/IPv69/parse.h include/IPv69/header.h include/IPv69/tweetnacl.h | $(BUILD)
	$(CC) $(CFLAGS) -o $(BUILD)/$@ tests/af69_test.c src/IPv69/parse.c $(CRYPTO)

af69d: src/IPv69/af69d.c src/IPv69/parse.c $(CRYPTO) include/IPv69/af69.h include/IPv69/parse.h include/IPv69/header.h include/IPv69/tweetnacl.h | $(BUILD)
	$(CC) $(CFLAGS) -o $(BUILD)/$@ src/IPv69/af69d.c src/IPv69/parse.c $(CRYPTO)

af69_raw: tests/af69_raw.c src/IPv69/parse.c $(CRYPTO) include/IPv69/af69.h include/IPv69/parse.h include/IPv69/header.h include/IPv69/tweetnacl.h | $(BUILD)
	$(CC) $(CFLAGS) -o $(BUILD)/$@ tests/af69_raw.c src/IPv69/parse.c $(CRYPTO)

ipv69-keygen: src/IPv69/ipv69-keygen.c $(CRYPTO) include/IPv69/tweetnacl.h | $(BUILD)
	$(CC) $(CFLAGS) -o $(BUILD)/$@ src/IPv69/ipv69-keygen.c $(CRYPTO)

ip69d: src/IPv69/ip69d.c src/IPv69/parse.c $(CRYPTO) include/IPv69/af69.h include/IPv69/parse.h include/IPv69/header.h include/IPv69/tweetnacl.h | $(BUILD)
	$(CC) $(CFLAGS) -o $(BUILD)/$@ src/IPv69/ip69d.c src/IPv69/parse.c $(CRYPTO)

ip69: src/IPv69/ip69.c | $(BUILD)
	$(CC) $(CFLAGS) -o $(BUILD)/$@ src/IPv69/ip69.c

.PHONY: all caps af69 af69_test af69d af69_raw ip69d ip69 ipv69-keygen
