#!/bin/sh
# PC side of docs/e2e-pc-phone.md: pc.sh <home> <tool> [args...]
# Runs a Windows build from the bench directory with an isolated identity.
# The Npcap adapter that matches this LAN is "Realtek".
set -e
BENCH=/mnt/c/Users/user/ipv69bench
H=$1; shift
T=$1; shift
cd "$BENCH"
WSLENV=HOME HOME="C:/Users/user/ipv69bench/$H" exec "./$T.exe" "$@"
