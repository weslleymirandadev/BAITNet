# IPv69 - build (C, static libc)
CC      := gcc
# static libc on Termux: bionic ships no libc.a (only .so), so ld.lld
# fails with "unable to find library -lc". Termux is detected by
# $PREFIX (set only there); override with `make STATIC=` if needed.
ifeq ($(PREFIX),)
STATIC  := -static
else
STATIC  :=
endif
CFLAGS  := -Wall -Wextra -O2 $(STATIC) -Iinclude -Ilib/ed25519/include
BUILD   := build

$(BUILD):
	mkdir -p $(BUILD)

# drop the sudo requirement: give CAP_NET_RAW to the binary (once per build)
caps: ipv69
	sudo setcap cap_net_raw+ep $(BUILD)/ipv69

# ed25519: standalone crypto library (also usable by the future stream
# transport / "own HTTPS" - see lib/ed25519/include/ed25519.h)
ED25519 := lib/ed25519/src/ed25519.c lib/ed25519/src/tweetnacl.c lib/ed25519/src/randombytes.c

# single binary, git-style subcommands (src/IPv69/main.c dispatches)
IPV69_SRC := src/IPv69/main.c src/IPv69/parse.c src/IPv69/af69d.c \
	src/IPv69/ipv69gw.c src/IPv69/ip69d.c src/IPv69/ip69.c \
	src/IPv69/keygen.c src/IPv69/keyring.c src/IPv69/l2.c \
	src/IPv69/mac1.c src/IPv69/ratelimit.c src/IPv69/gwfile.c \
	src/IPv69/help.c \
	tests/af69_raw.c \
	tests/icsp_test.c src/ICSP/icsp.c src/ICSP/icsp_handshake.c \
	src/ICSP/icsp_data.c src/ICSP/icsp_life.c src/ICSP/icsp_session.c

ipv69: $(BUILD)/ipv69

$(BUILD)/ipv69: $(IPV69_SRC) $(ED25519) include/IPv69/af69.h include/IPv69/parse.h \
	include/IPv69/header.h include/IPv69/l2.h include/IPv69/plat.h \
	include/ICSP/icsp.h lib/ed25519/include/ed25519.h | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $(IPV69_SRC) $(ED25519)

# example tool built on the ICSP session layer (standalone binary,
# NOT part of ipv69)
ICSP_SRC := src/ICSP/icsp.c src/ICSP/icsp_handshake.c \
	src/ICSP/icsp_data.c src/ICSP/icsp_life.c src/ICSP/icsp_session.c
CHAT_SRC := examples/icsp_chat.c src/IPv69/keyring.c src/IPv69/parse.c \
	src/IPv69/l2.c src/IPv69/mac1.c src/IPv69/ratelimit.c \
	src/IPv69/gwfile.c $(ICSP_SRC) $(ED25519)
# group-chat hub: same libs, multi-association server (POSIX poll —
# Linux only, like tun)
HUB_SRC := examples/icsp_hub.c src/IPv69/keyring.c src/IPv69/parse.c \
	src/IPv69/l2.c src/IPv69/mac1.c src/IPv69/ratelimit.c \
	src/IPv69/gwfile.c $(ICSP_SRC) $(ED25519)

.PHONY: all ipv69 chat hub win lib libwin libdemo

all: ipv69 chat

chat: $(BUILD)/icsp_chat

$(BUILD)/icsp_chat: $(CHAT_SRC) include/ICSP/icsp.h include/IPv69/keyring.h | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $(CHAT_SRC)

hub: $(BUILD)/icsp_hub

$(BUILD)/icsp_hub: $(HUB_SRC) include/ICSP/icsp.h include/IPv69/keyring.h | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $(HUB_SRC)

# --- Windows build (MinGW + Npcap): full ipv69.exe + chat, raw L2 via
# libpcap. Linux-only commands (tun/lease/status) are excluded and
# report "not supported on Windows".
# gcc.exe runs through WSL interop: the CWD is translated, so relative
# paths work, but the Npcap SDK needs a Windows-style path (fwd slashes).
# Toolchain paths are probed, not hardcoded: override with
#   make win WIN_CC=/path/to/gcc.exe WIN_SDK=C:/path/to/npcap-sdk
# Npcap SDK zip: https://npcap.com/dist/npcap-sdk-1.13.zip
WIN_USER   ?= $(shell cmd.exe /c echo %USERNAME% 2>/dev/null | tr -d '\r')
WIN_CC     ?= $(or $(firstword $(wildcard \
	/mnt/c/ProgramData/mingw64/mingw64/bin/gcc.exe \
	/mnt/c/msys64/mingw64/bin/gcc.exe \
	/mnt/c/mingw64/bin/gcc.exe \
	/mnt/c/MinGW/bin/gcc.exe)),gcc.exe)
WIN_SDK    ?= $(if $(WIN_USER),C:/Users/$(WIN_USER)/npcap-sdk,C:/npcap-sdk)
WIN_CFLAGS := -Wall -Wextra -O2 -static -Iinclude -Ilib/ed25519/include \
	-I$(WIN_SDK)/Include
WIN_LIBS   := $(WIN_SDK)/Lib/x64/wpcap.lib -lws2_32 -liphlpapi -lbcrypt
WIN_SRC    := examples/icsp_chat.c src/IPv69/keyring.c src/IPv69/parse.c \
	src/IPv69/l2_win.c src/IPv69/mac1.c src/IPv69/ratelimit.c \
	src/IPv69/gwfile.c $(ICSP_SRC) $(ED25519)
IPV69_WIN_SRC := src/IPv69/main.c src/IPv69/parse.c src/IPv69/af69d.c \
	src/IPv69/ipv69gw.c src/IPv69/keygen.c src/IPv69/keyring.c \
	src/IPv69/l2_win.c src/IPv69/mac1.c src/IPv69/ratelimit.c \
	src/IPv69/gwfile.c \
	src/IPv69/help.c \
	tests/af69_raw.c tests/icsp_test.c $(ICSP_SRC) $(ED25519)

win: $(BUILD)/ipv69.exe $(BUILD)/icsp_chat.exe

$(BUILD)/ipv69.exe: $(IPV69_WIN_SRC) include/IPv69/plat.h include/IPv69/af69.h | $(BUILD)
	$(WIN_CC) $(WIN_CFLAGS) -o $@ $(IPV69_WIN_SRC) $(WIN_LIBS)
	chmod +x $@

$(BUILD)/icsp_chat.exe: $(WIN_SRC) include/ICSP/icsp.h include/IPv69/l2.h | $(BUILD)
	$(WIN_CC) $(WIN_CFLAGS) -o $@ $(WIN_SRC) $(WIN_LIBS)
	chmod +x $@

# --- static library (the reusable core, no cmd_* entry points) ---
# Everything a program needs to speak IPv69/ICSP without the CLI
# dispatcher: parse, keyring, L2 backend, mac1/ratelimit, gateway file,
# the ICSP session layer and the ed25519 crypto. Build with:
#   make lib      # POSIX (AF_PACKET L2) -> build/libipv69.a
#   make libwin   # MinGW (Npcap L2)     -> build/libipv69_win.a
# Link example:  $(CC) app.c build/libipv69.a -Iinclude -Ilib/ed25519/include
# Headers keep their module paths (#include "IPv69/parse.h" etc.); the
# umbrella include/ipv69.h pulls everything in with one #include.
LIB_POSIX := src/IPv69/parse.c src/IPv69/l2.c src/IPv69/keyring.c \
	src/IPv69/mac1.c src/IPv69/ratelimit.c src/IPv69/gwfile.c \
	src/ICSP/icsp.c src/ICSP/icsp_handshake.c src/ICSP/icsp_data.c \
	src/ICSP/icsp_life.c src/ICSP/icsp_session.c
LIB_WIN := src/IPv69/parse.c src/IPv69/l2_win.c src/IPv69/keyring.c \
	src/IPv69/mac1.c src/IPv69/ratelimit.c src/IPv69/gwfile.c \
	src/ICSP/icsp.c src/ICSP/icsp_handshake.c src/ICSP/icsp_data.c \
	src/ICSP/icsp_life.c src/ICSP/icsp_session.c

# object names mirror the source path (src/IPv69/parse.c ->
# lib-obj/posix/src_IPv69_parse.o) so same-named files never clash
LIB_OBJ_DIR := $(BUILD)/lib-obj

define lib_compile_posix
$(CC) $(CFLAGS) -c $(1) -o $(LIB_OBJ_DIR)/posix/$(subst /,_,$(1:.c=.o))
endef

define lib_compile_win
$(WIN_CC) $(WIN_CFLAGS) -c $(1) -o $(LIB_OBJ_DIR)/win/$(subst /,_,$(1:.c=.o))
endef

lib: $(BUILD)/libipv69.a

$(BUILD)/libipv69.a: $(LIB_POSIX) $(ED25519) $(wildcard include/IPv69/*.h include/ICSP/*.h) | $(BUILD)
	@mkdir -p $(LIB_OBJ_DIR)/posix
	@$(foreach f,$(LIB_POSIX) $(ED25519),$(call lib_compile_posix,$(f)) || exit 1;)
	ar rcs $@ $(LIB_OBJ_DIR)/posix/*.o

libwin: $(BUILD)/libipv69_win.a

$(BUILD)/libipv69_win.a: $(LIB_WIN) $(ED25519) $(wildcard include/IPv69/*.h include/ICSP/*.h) | $(BUILD)
	@mkdir -p $(LIB_OBJ_DIR)/win
	@$(foreach f,$(LIB_WIN) $(ED25519),$(call lib_compile_win,$(f)) || exit 1;)
	ar rcs $@ $(LIB_OBJ_DIR)/win/*.o

# demo: an app that links ONLY the static library (see docs/lib-api.md).
# Proves the library is self-contained — no source-list linking needed.
libdemo: $(BUILD)/libipv69.a
	$(CC) $(CFLAGS) -o $(BUILD)/chat_lib examples/chat_lib.c $(BUILD)/libipv69.a
