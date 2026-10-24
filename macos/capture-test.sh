#!/bin/sh
# Capture test: start a FaceTime call first, then: macos/capture-test.sh [--seconds 20] [--allow-cloud]
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
tail -n +1 -F "$LOG" 2>/dev/null &   # -F: the listener replaces the file when it starts
TAIL=$!
# Wait for the test to finish. The first launch after a build can take a while to start.
started=0; i=0
while [ $i -lt 240 ]; do
  if pgrep -q -f "$BIN"; then started=1; elif [ $started = 1 ]; then break; fi
  if [ $started = 0 ] && [ $i -ge 40 ]; then echo "The listener didn't start. Run it again."; break; fi
  sleep 0.5; i=$((i + 1))
done
while [ $started = 1 ] && pgrep -q -f "$BIN"; do sleep 1; done
sleep 1
kill $TAIL 2>/dev/null
