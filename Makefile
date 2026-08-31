# IPv69 - build (C, static libc)
CC      := gcc
CFLAGS  := -Wall -Wextra -O2 -static -Iinclude -Ilib/ed25519/include
BUILD   := build

all: ipv69

$(BUILD):
	mkdir -p $(BUILD)

# drop the sudo requirement: give CAP_NET_RAW to the binary (once per build)
caps: ipv69
	sudo setcap cap_net_raw+ep $(BUILD)/ipv69

# AF_69: kernel module + userspace test
AF69_KDIR ?= $(HOME)/wsl-kernel

# ed25519: standalone crypto library (also usable by the future stream
# transport / "own HTTPS" - see lib/ed25519/include/ed25519.h)
ED25519 := lib/ed25519/src/ed25519.c lib/ed25519/src/tweetnacl.c lib/ed25519/src/randombytes.c

# single binary, git-style subcommands (src/IPv69/main.c dispatches)
IPV69_SRC := src/IPv69/main.c src/IPv69/parse.c src/IPv69/af69d.c \
	src/IPv69/ipv69gw.c src/IPv69/ip69d.c src/IPv69/ip69.c \
	src/IPv69/keygen.c src/IPv69/keyring.c src/IPv69/l2.c \
	src/IPv69/help.c \
	tests/af69_raw.c tests/af69_test.c \
	tests/icsp_test.c src/ICSP/icsp.c src/ICSP/icsp_handshake.c \
	src/ICSP/icsp_data.c src/ICSP/icsp_life.c

ipv69: $(IPV69_SRC) $(ED25519) include/IPv69/af69.h include/IPv69/parse.h \
	include/IPv69/header.h include/IPv69/l2.h include/ICSP/icsp.h \
	lib/ed25519/include/ed25519.h | $(BUILD)
	$(CC) $(CFLAGS) -o $(BUILD)/$@ $(IPV69_SRC) $(ED25519)

af69:
	$(MAKE) -C kernel/af69 KDIR=$(AF69_KDIR)

# example tool built on the ICSP API (standalone binary, NOT part of ipv69)
ICSP_SRC := src/ICSP/icsp.c src/ICSP/icsp_handshake.c \
	src/ICSP/icsp_data.c src/ICSP/icsp_life.c
CHAT_SRC := examples/icsp_chat.c src/IPv69/keyring.c src/IPv69/parse.c \
	src/IPv69/l2.c $(ICSP_SRC) $(ED25519)

chat: $(CHAT_SRC) include/ICSP/icsp.h include/IPv69/keyring.h | $(BUILD)
	$(CC) $(CFLAGS) -o $(BUILD)/icsp_chat $(CHAT_SRC)

# legacy targets -> single binary (kept so old scripts still work)
af69_test af69d af69_raw keygen ip69d ip69 ipv69gw: ipv69
	@ln -sf ipv69 $(BUILD)/$@
