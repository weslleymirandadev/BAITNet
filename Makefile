# IPv69 - build (C + libc estatica)
CC      := gcc
CFLAGS  := -Wall -Wextra -O2 -static -Isrc/IPv69
BUILD   := build

BINS := ipv69 ipv69_send

all: $(BINS)

$(BUILD):
	mkdir -p $(BUILD)

ipv69: tests/ipv69.c src/IPv69/parse.c src/IPv69/header.h src/IPv69/parse.h | $(BUILD)
	$(CC) $(CFLAGS) -o $(BUILD)/$@ tests/ipv69.c src/IPv69/parse.c

ipv69_send: tests/send.c src/IPv69/header.h | $(BUILD)
	$(CC) $(CFLAGS) -o $(BUILD)/$@ tests/send.c

.PHONY: all
