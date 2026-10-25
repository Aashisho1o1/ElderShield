#!/bin/sh
# Start → fail → restart drill: breaks the app the ways it could break in front of a judge (daemon crash,
# sensor crash, database crash, port squatter, wrong start order, cold start from nothing) and checks that
# ./start.sh makes it whole again each time. Run it before a demo: ./drill.sh  (about 2 minutes; it
# restarts the local SpacetimeDB, so not while a call is live).
cd "$(dirname "$0")" || exit 1
PATH="$HOME/.local/bin:$PATH"
if pgrep -f "sh (\./)?start\.sh --watch" >/dev/null; then
  echo "./start.sh --watch is running: it would restart what this drill kills. Ctrl-C it first, then run the drill."; exit 1
fi
D=http://127.0.0.1:8777
# the same anchored process patterns start.sh uses (a shell merely mentioning these names must not count)
DAEMON_RE='^([^ ]*/)?[Pp]ython[0-9.]* ([^ ]*/)?server\.py'
SENSOR_RE='^([^ ]*/)?[Pp]ython[0-9.]* (-u )?([^ ]*/)?device_watch\.py'
VITE_RE='^node .*vite --port 5174'
STDB_RE='^[^ ]*spacetimedb-standalone'
PASS=0; FAIL=0
pass() { printf '  PASS %s\n' "$1"; PASS=$((PASS + 1)); }
fail() { printf '  FAIL %s\n' "$1"; FAIL=$((FAIL + 1)); }
check() { if eval "$2"; then pass "$1"; else fail "$1"; fi; }
count() { pgrep -f "$1" | wc -l | tr -d ' '; }
state() { curl -sf -m 5 $D/state; }
callers() { state | python3 -c "import sys,json; print(len(json.load(sys.stdin)['track']['contacts']))" 2>/dev/null; }
whole() {  # the app is whole: one of each process, healthy, 3 seeded callers, sensor live
  check "$1: exactly one daemon / sensor / family page / database" \
    "[ $(count "$DAEMON_RE") = 1 ] && [ $(count "$SENSOR_RE.* --listen") = 1 ] && [ $(count "$VITE_RE") = 1 ] && [ $(count "$STDB_RE") = 1 ]"
  check "$1: daemon healthy and the journal still has its 3 callers" "[ \"$(callers)\" = 3 ]"
  check "$1: sensor live and listening" "state | grep -q '\"sensor_live\":true'"
  check "$1: family page answering" "curl -sf -m 3 -o /dev/null http://127.0.0.1:5174/"
}
run_start() { ./start.sh "$@" >logs/drill-start.log 2>&1; echo "    (start.sh exit $? in $SECONDS s; $(grep -c '✓' logs/drill-start.log) ✓, $(grep -c '✗' logs/drill-start.log) ✗)"; }
SECONDS=0

echo "A. ./start.sh when everything is already running must change nothing"
BEFORE="$(pgrep -f "$DAEMON_RE") $(pgrep -f "$SENSOR_RE") $(pgrep -f "$STDB_RE")"
SECONDS=0; run_start --quick
AFTER="$(pgrep -f "$DAEMON_RE") $(pgrep -f "$SENSOR_RE") $(pgrep -f "$STDB_RE")"
check "A: same processes before and after (idempotent)" "[ \"$BEFORE\" = \"$AFTER\" ]"
whole A

echo "B. the daemon crashes mid-demo"
pkill -f "$DAEMON_RE"; sleep 1
check "B: daemon is down" "! curl -sf -m 2 -o /dev/null $D/health"
SECONDS=0; run_start --quick
whole B

echo "C. the sensor dies mid-demo"
pkill -f "$SENSOR_RE"; sleep 7
check "C: daemon reports the sensor gone and closes any open call" "state | grep -q '\"sensor_live\":false'"
SECONDS=0; run_start --quick
whole C

echo "D. SpacetimeDB itself dies mid-demo"
pkill -f "$STDB_RE"; sleep 2
check "D: daemon can't serve state while the database is down" "! curl -sf -m 5 -o /dev/null $D/state"
SECONDS=0; run_start --quick
whole D
check "D: her circle settings survived (household row present)" "state | grep -q '\"elder_name\"'"

echo "E. something else is squatting on the daemon's port"
pkill -f "$DAEMON_RE"; sleep 1
python3 -m http.server 8777 --bind 127.0.0.1 >/dev/null 2>&1 & SQUAT=$!
sleep 1
./start.sh --quick >logs/drill-start.log 2>&1; RC=$?
check "E: start.sh refuses, names the squatter, exits 1" "[ $RC = 1 ] && grep -q 'port 8777 is taken' logs/drill-start.log"
kill $SQUAT; sleep 1
SECONDS=0; run_start --quick
whole E

echo "F. wrong start order: daemon started before the database"
./start.sh --stop >/dev/null 2>&1; pkill -f "$STDB_RE"; sleep 2
( set -a; . ./.env; set +a; nohup python3 server.py >logs/drill-daemon-first.log 2>&1 & )
sleep 3
check "F: daemon is waiting, not dead" "pgrep -f \"$DAEMON_RE\" >/dev/null && grep -q 'Waiting for SpacetimeDB' logs/drill-daemon-first.log"
SECONDS=0; run_start --quick
whole F

echo "G. cold start from nothing (as after a reboot): database, module, daemon, sensor, page, self-test"
./start.sh --stop >/dev/null 2>&1; pkill -f "$STDB_RE"; sleep 2
check "G: nothing running" "[ $(count "$DAEMON_RE") = 0 ] && [ $(count "$SENSOR_RE") = 0 ] && [ $(count "$STDB_RE") = 0 ]"
SECONDS=0; run_start
whole G
check "G: listener self-test heard the test line" "grep -q 'heard: .*pension' logs/drill-start.log"
check "G: no ✗ in the start output" "! grep -q '✗' logs/drill-start.log"

echo "H. ./start.sh --check on the running app is all green"
./start.sh --check >logs/drill-check.log 2>&1; RC=$?
check "H: --check exits 0 with the self-test passing" "[ $RC = 0 ] && grep -q 'heard: .*pension' logs/drill-check.log"

echo
echo "$PASS passed, $FAIL failed"
[ $FAIL = 0 ]
