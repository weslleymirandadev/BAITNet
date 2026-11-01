#!/bin/sh
# Phone side of docs/e2e-pc-phone.md: phone.sh <home> <tool> [args...]
# The static arm64 binaries live in /data/local/tmp/ipv69bench and run as
# root directly on Android (no NetHunter chroot needed for that: `su` from
# adb cannot chroot on every ROM).
# Optional env: TMO=<seconds> (default 30).
set -e
H=$1; shift
T=$1; shift
ADB=${ADB:-/mnt/c/Users/user/AppData/Local/Android/Sdk/platform-tools/adb.exe}
TMO=${TMO:-30}
"$ADB" shell su -c "HOME=/data/local/tmp/ipv69bench/$H timeout $TMO /data/local/tmp/ipv69bench/$T $*"
