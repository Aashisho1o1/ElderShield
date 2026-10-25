#!/bin/sh
# One command to bring ElderShield up for a demo, in the right order, with a check at every step,
# so "I started it but the call didn't work" can't happen quietly.
#
#   ./start.sh            start whatever isn't running (database → module → daemon → sensor → family page),
#                         then run the readiness checks and print the demo checklist
#   ./start.sh --check    only the checks, including a 10-second listener self-test (it speaks a test line
#                         through the Mac's speaker and shows what the listener heard)
#   ./start.sh --quick    start without the listener self-test
#   ./start.sh --stop     stop the daemon, sensor, listener and family page (the database keeps running)
#
# Logs go to logs/. Jev needs OPENROUTER_API_KEY in .env (git-ignored); without it the phrase rules run alone.
set -u
cd "$(dirname "$0")" || exit 1
PATH="$HOME/.local/bin:$PATH"
mkdir -p logs
[ -f .env ] && { set -a; . ./.env; set +a; }

STDB="${SPACETIME_URL:-http://127.0.0.1:3000}"
DB="${SPACETIME_DB:-eldershield}"
DAEMON="http://127.0.0.1:${ELDERSHIELD_PORT:-8777}"
FAMILY_PORT=5174
MODE="${1:-start}"
PROBLEMS=0

say_ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; }
say_bad()  { printf '  \033[31m✗\033[0m %s\n' "$1"; PROBLEMS=$((PROBLEMS + 1)); }
say_warn() { printf '  \033[33m!\033[0m %s\n' "$1"; }
up()       { curl -sf -m 2 -o /dev/null "$1"; }
wait_for() { # wait_for <url> <seconds> <what>
  i=0; while [ $i -lt "$2" ]; do up "$1" && return 0; sleep 1; i=$((i + 1)); done
  say_bad "$3 didn't come up in $2 s"; return 1
}
state() { curl -sf -m 5 "$DAEMON/state" 2>/dev/null; }
json()  { python3 -c "import sys, json; d = json.load(sys.stdin); print($1)" 2>/dev/null; }

if [ "$MODE" = "--stop" ]; then
  pkill -f "device_watch.py"; pkill -f "Listen.app/Contents/MacOS/listen"; pkill -f "eldershield-warning"
  pkill -f "python3 server.py"; pkill -f "Python server.py"
  pkill -f "vite --port $FAMILY_PORT"
  echo "Stopped the daemon, sensor, listener and family page. SpacetimeDB keeps running (your data is safe);"
  echo "to stop it too: pkill -f spacetimedb-standalone"
  exit 0
fi

echo "ElderShield"
echo "— prerequisites"
command -v spacetime >/dev/null || { say_bad "spacetime CLI not found: curl -sSf https://install.spacetimedb.com | sh"; exit 1; }
python3 -c "import fastapi, uvicorn, pydantic" 2>/dev/null && say_ok "python deps" || { say_bad "pip3 install -r requirements.txt"; exit 1; }
command -v swiftc >/dev/null && say_ok "swiftc (builds the alert window and listener)" || say_bad "swiftc missing: xcode-select --install"
[ -n "${OPENROUTER_API_KEY:-}${TYPESAFE_API_KEY:-}" ] && say_ok "Jev key loaded from .env" || say_warn "no Jev key in .env: phrase rules only (no 'pension clears' catch)"

echo "— database"
if up "$STDB/v1/ping"; then say_ok "SpacetimeDB answering at $STDB"
elif [ "$MODE" = "--check" ]; then say_bad "SpacetimeDB not running (spacetime start)"
else
  nohup spacetime start --listen-addr 127.0.0.1:3000 --non-interactive >logs/spacetime.log 2>&1 &
  wait_for "$STDB/v1/ping" 30 "SpacetimeDB" && say_ok "SpacetimeDB started (logs/spacetime.log)"
fi
if up "$STDB/v1/ping"; then
  if spacetime describe "$DB" --server local --json >/dev/null 2>&1; then
    if [ spacetimedb/src/index.ts -nt logs/.published ] 2>/dev/null || [ ! -f logs/.published ]; then
      if [ "$MODE" = "--check" ]; then say_warn "module source is newer than the last publish: ./start.sh will republish"
      else spacetime publish "$DB" --server local --yes >logs/publish.log 2>&1 && touch logs/.published \
             && say_ok "module republished (source had changed; data kept)" || say_bad "publish failed: see logs/publish.log"; fi
    else say_ok "module '$DB' published and current"; fi
  elif [ "$MODE" = "--check" ]; then say_bad "database '$DB' not published: spacetime publish $DB --server local"
  else spacetime publish "$DB" --server local --yes >logs/publish.log 2>&1 && touch logs/.published \
         && say_ok "module published to '$DB'" || say_bad "publish failed: see logs/publish.log"; fi
fi

echo "— daemon"
if up "$DAEMON/health"; then say_ok "daemon answering at $DAEMON"
elif pgrep -f "[Pp]ython3? server.py" >/dev/null; then       # started before the database: it waits, then connects
  wait_for "$DAEMON/health" 25 "the already-running daemon" && say_ok "daemon was waiting for the database; now answering" \
    || { say_bad "a daemon process exists but never answered: ./start.sh --stop, then ./start.sh (logs/server.log)"; }
elif [ "$MODE" = "--check" ]; then say_bad "daemon not running (python3 server.py)"
elif lsof -nP -iTCP:"${ELDERSHIELD_PORT:-8777}" -sTCP:LISTEN >/dev/null 2>&1; then
  say_bad "port ${ELDERSHIELD_PORT:-8777} is taken by something that isn't answering: $(lsof -nP -tiTCP:"${ELDERSHIELD_PORT:-8777}" -sTCP:LISTEN | head -1) — ./start.sh --stop, then try again"
else
  nohup python3 server.py >logs/server.log 2>&1 &
  wait_for "$DAEMON/health" 20 "daemon" && say_ok "daemon started (logs/server.log)" || tail -5 logs/server.log
fi
if up "$DAEMON/health"; then
  S=$(state)
  [ "$(echo "$S" | json "d['jev']['enabled']")" = "True" ] && say_ok "Jev on ($(echo "$S" | json "d['jev']['model'] or 'no call yet'"))" || say_warn "Jev off in the running daemon (start it with .env loaded: ./start.sh does)"
  echo "$S" | json "len(d['track']['contacts'])" | grep -q "^0$" && say_warn "journal is empty: click 'Load 3-week story' before the demo" || say_ok "journal has $(echo "$S" | json "len(d['track']['contacts'])") callers"
fi

echo "— sensor (calls, remote control, listening)"
if pgrep -f "device_watch.py" >/dev/null; then
  i=0; while [ $i -lt 12 ]; do [ "$(state | json "d['device']['sensor_live']")" = "True" ] && break; sleep 1; i=$((i + 1)); done
  if [ $i -ge 12 ]; then say_bad "sensor process exists but the daemon hasn't heard from it in 12 s: ./start.sh --stop, then ./start.sh (logs/sensor.log)"
  elif pgrep -f "device_watch.py --listen" >/dev/null; then say_ok "sensor live, listening"
  else say_warn "sensor live but WITHOUT --listen: calls are detected but not heard (./start.sh --stop, then ./start.sh)"; fi
elif [ "$MODE" = "--check" ]; then say_bad "sensor not running (python3 device_watch.py --listen)"
else
  nohup python3 -u device_watch.py --listen >logs/sensor.log 2>&1 &
  i=0; while [ $i -lt 90 ]; do [ "$(state | json "d['device']['sensor_live']")" = "True" ] && break; sleep 1; i=$((i + 1)); done
  [ $i -lt 90 ] && say_ok "sensor live, listening (logs/sensor.log)" || { say_bad "sensor didn't report in 90 s"; tail -5 logs/sensor.log; }
fi
ls "$HOME/Library/Application Support/CallHistoryDB" >/dev/null 2>&1 && say_ok "call history readable: callers get their names" \
  || say_warn "no Full Disk Access for this terminal: callers show as 'Unknown caller' (System Settings → Privacy & Security → Full Disk Access → add Terminal/VS Code, then ./start.sh --stop && ./start.sh), or rehearse with --caller Daniel"

echo "— her circle's page"
if up "http://127.0.0.1:$FAMILY_PORT/"; then say_ok "family page at http://127.0.0.1:$FAMILY_PORT"
elif [ "$MODE" = "--check" ]; then say_warn "family page not running (cd family && npm run dev)"
elif [ ! -x family/node_modules/.bin/vite ]; then say_warn "family/node_modules missing: cd family && npm install"
else
  (cd family && nohup node_modules/.bin/vite --port $FAMILY_PORT --strictPort --host 127.0.0.1 >../logs/family.log 2>&1 &)
  wait_for "http://127.0.0.1:$FAMILY_PORT/" 20 "family page" && say_ok "family page started at http://127.0.0.1:$FAMILY_PORT (logs/family.log)"
fi

if [ "$MODE" != "--quick" ]; then
  echo "— listener self-test (12 s: the Mac speaks a test line; the listener must hear and transcribe it)"
  if pgrep -f "Listen.app/Contents/MacOS/listen --post" >/dev/null; then say_warn "a call is live right now; skipping the self-test"
  else
    : >logs/listener-selftest.log
    # speak only once the tap is confirmed live (the listener's launch time varies), then give it
    # a quiet second so the recognizer rotates its first chunk before the sentence starts
    ( i=0; while [ $i -lt 100 ] && ! grep -q "✓ tapping system audio" logs/listener-selftest.log 2>/dev/null; do sleep 0.2; i=$((i + 1)); done
      sleep 1; say -r 180 "I'm a bit short until my pension clears. Could you help me out?" ) &
    macos/capture-test.sh --seconds 14 >logs/listener-selftest.log 2>&1
    sleep 2                                   # the listener writes its RESULT lines 1.5 s after it stops
    L=macos/capture-test.log                  # the listener's own log; the tail above can miss its last lines
    grep -q "✓ tapping system audio" $L && say_ok "system audio tap allowed" || say_bad "system audio tap refused: System Settings → Privacy & Security → Screen & System Audio Recording → allow 'ElderShield listener'"
    grep -q "✓ speech is transcribed on this Mac" $L && say_ok "on-device speech allowed" || say_bad "speech recognition not allowed or model missing: see $L"
    T=$(grep "RESULT: transcript" $L | sed 's/.*→ //'); [ -n "$T" ] || T=$(grep "  transcript: " $L | tail -1 | sed 's/.*transcript: //')
    case "$T" in *pension*) say_ok "heard: $T";; "") say_bad "heard nothing: is the Mac muted or on headphones? (the listener hears the speaker output; see $L)";; *) say_warn "heard: $T";; esac
  fi
fi

echo
if [ $PROBLEMS -eq 0 ]; then
  echo "Ready. Her page: $DAEMON · her circle: http://127.0.0.1:$FAMILY_PORT"
  echo "Demo: Reset → Load 3-week story → add Sarah → open the family page in a private window with her code →"
  echo "      start the call (real FaceTime, or: python3 device_watch.py --pretend facetime --caller Daniel --script demo/romance_call.txt"
  echo "      after ./start.sh --stop of the sensor) → send the \$8,500 wire."
else
  echo "$PROBLEMS problem(s) above. Fix them before the demo; ./start.sh --check re-runs the checks."
  exit 1
fi
