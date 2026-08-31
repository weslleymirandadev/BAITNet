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
	src/IPv69/keygen.c src/IPv69/keyring.c tests/af69_raw.c tests/af69_test.c

ipv69: $(IPV69_SRC) $(ED25519) include/IPv69/af69.h include/IPv69/parse.h \
	include/IPv69/header.h lib/ed25519/include/ed25519.h | $(BUILD)
	$(CC) $(CFLAGS) -o $(BUILD)/$@ $(IPV69_SRC) $(ED25519)

af69:
	$(MAKE) -C kernel/af69 KDIR=$(AF69_KDIR)

# legacy targets -> single binary (kept so old scripts still work)
af69_test af69d af69_raw keygen ip69d ip69 ipv69gw: ipv69
	@ln -sf ipv69 $(BUILD)/$@
