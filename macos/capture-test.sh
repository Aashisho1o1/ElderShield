#!/bin/sh
# Builds and runs the capture test. Start a FaceTime call first, then: macos/capture-test.sh
# The test is an .app launched with `open`, because macOS attributes permission prompts to the
# app that launched a program; from a terminal that would be the terminal itself, which has no
# speech/audio permission strings, and the program is killed at the first prompt.
set -e
cd "$(dirname "$0")"
APP="CaptureTest.app"
BIN="$APP/Contents/MacOS/capture-test"
if [ ! -x "$BIN" ] || [ CaptureTest.swift -nt "$BIN" ] || [ CaptureTest-Info.plist -nt "$BIN" ]; then
  echo "building…"
  mkdir -p "$APP/Contents/MacOS"
  cp CaptureTest-Info.plist "$APP/Contents/Info.plist"
  swiftc -O CaptureTest.swift -o "$BIN" 2>&1 | grep -v "warning: forming\|AudioObjectGetPropertyData\|^ *\^" || true
  codesign --force --sign - "$APP" 2>/dev/null     # ad-hoc: ties the binary to the bundle for TCC
fi
LOG="$PWD/capture-test.log"
: > "$LOG"
open -n "$APP" --args --log "$LOG" "$@"
echo "(if macOS asks to allow System Audio Recording or Speech Recognition, click Allow)"
tail -n +1 -f "$LOG" &
TAIL=$!
sleep 2
while pgrep -q -f "$BIN"; do sleep 1; done
sleep 1
kill $TAIL 2>/dev/null
