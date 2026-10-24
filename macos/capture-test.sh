#!/bin/sh
# Capture test: start a FaceTime call first, then: macos/capture-test.sh [--seconds 20]
# It builds the listener app (shared with device_watch.py --listen) and runs it in test mode.
# The listener is an .app launched with `open`, because macOS attributes permission prompts to
# the app that launched a program; from a terminal that would be the terminal itself, which has
# no speech/audio permission strings, and the program is killed at the first prompt.
set -e
cd "$(dirname "$0")"
python3 -c 'import sys; sys.path.insert(0, ".."); import device_watch as d; sys.exit(0 if d.build_listener() else 1)'
BIN="Listen.app/Contents/MacOS/listen"
LOG="$PWD/capture-test.log"
: > "$LOG"
open -n Listen.app --args --log "$LOG" "$@"
echo "(if macOS asks to allow System Audio Recording or Speech Recognition, click Allow)"
tail -n +1 -f "$LOG" &
TAIL=$!
sleep 2
while pgrep -q -f "$BIN"; do sleep 1; done
sleep 1
kill $TAIL 2>/dev/null
