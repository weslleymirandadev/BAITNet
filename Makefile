# IPv69 - build (C + libc estatica)
CC      := gcc
CFLAGS  := -Wall -Wextra -O2 -static -Iinclude
BUILD   := build

BINS := ipv69 ipv69_send af69_ping

all: $(BINS)

$(BUILD):
	mkdir -p $(BUILD)

ipv69: tests/ipv69.c src/IPv69/parse.c src/IPv69/iface.c include/IPv69/header.h include/IPv69/parse.h include/IPv69/iface.h | $(BUILD)
	$(CC) $(CFLAGS) -o $(BUILD)/$@ tests/ipv69.c src/IPv69/parse.c src/IPv69/iface.c

ipv69_send: tests/send.c src/IPv69/iface.c include/IPv69/header.h include/IPv69/iface.h | $(BUILD)
	$(CC) $(CFLAGS) -o $(BUILD)/$@ tests/send.c src/IPv69/iface.c

af69_ping: tests/af69_ping.c include/IPv69/af69.h | $(BUILD)
	$(CC) $(CFLAGS) -o $(BUILD)/$@ tests/af69_ping.c

# remove a necessidade de sudo: da CAP_NET_RAW aos binarios (uma vez por build)
caps: $(BINS)
	sudo setcap cap_net_raw+ep $(BUILD)/ipv69 $(BUILD)/ipv69_send

.PHONY: all caps
