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

af69:
	$(MAKE) -C kernel/af69 KDIR=$(AF69_KDIR)

af69_test: tests/af69_test.c src/IPv69/parse.c include/IPv69/af69.h include/IPv69/parse.h include/IPv69/header.h | $(BUILD)
	$(CC) $(CFLAGS) -o $(BUILD)/$@ tests/af69_test.c src/IPv69/parse.c

af69d: src/IPv69/af69d.c src/IPv69/parse.c include/IPv69/af69.h include/IPv69/parse.h include/IPv69/header.h | $(BUILD)
	$(CC) $(CFLAGS) -o $(BUILD)/$@ src/IPv69/af69d.c src/IPv69/parse.c

af69_raw: tests/af69_raw.c src/IPv69/parse.c include/IPv69/af69.h include/IPv69/parse.h include/IPv69/header.h | $(BUILD)
	$(CC) $(CFLAGS) -o $(BUILD)/$@ tests/af69_raw.c src/IPv69/parse.c

.PHONY: all caps af69 af69_test af69d af69_raw
