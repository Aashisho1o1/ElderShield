"""
Tells ElderShield what is happening on this Mac right now, and shows its private warnings.

  - A live call: FaceTime (which also carries iPhone calls on a Mac) or another call app is
    running while the microphone is in use; and who it's with, if the Mac's call history is
    readable (System Settings → Privacy & Security → Full Disk Access for this terminal).
  - Remote control: AnyDesk, TeamViewer and similar apps are running.
  - With --listen: what is said on the call, heard on this Mac by macos/Listen.swift.

It reports to the daemon every 2 s and shows the daemon's alerts in a window that screen
sharing and screen capture can't see (macos/Warning.swift).

    python device_watch.py                                   # real sensors
    python device_watch.py --listen                          # also listen to calls (opt-in)
    python device_watch.py --pretend facetime --caller Daniel --script demo/romance_call.txt
                                                             # rehearse the demo without a real call
    python device_watch.py --speak                           # also say alerts aloud (headphones only)

Without --listen it needs no macOS permissions: it reads the process list and whether the
microphone is in use, never audio or screen contents.
"""

import argparse
import ctypes
import ctypes.util
import json
import shutil
import signal
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

DAEMON = "http://127.0.0.1:8777"
HERE = Path(__file__).resolve().parent
MACOS = HERE / "macos"
WARNING_BIN = MACOS / "eldershield-warning"
LISTEN_APP = MACOS / "Listen.app"
CALL_HISTORY = Path.home() / "Library/Application Support/CallHistoryDB/CallHistory.storedata"

# Matched against each running process's executable path, lower-cased.
CALL_APPS = {"/facetime.app/": "FaceTime", "/zoom.us.app/": "Zoom", "/whatsapp.app/": "WhatsApp",
             "/microsoft teams.app/": "Teams", "/msteams.app/": "Teams", "/skype.app/": "Skype",
             "/webex.app/": "Webex"}
REMOTE_ACCESS = {"anydesk": "AnyDesk", "teamviewer": "TeamViewer", "screenconnect": "ScreenConnect",
                 "connectwisecontrol": "ScreenConnect", "rustdesk": "RustDesk", "splashtop": "Splashtop",
                 "logmein": "LogMeIn", "gotoresolve": "GoTo", "remoting_me2me_host": "Chrome Remote Desktop",
                 "screensharingd": "macOS Screen Sharing"}


def running_apps(paths: list[str]) -> tuple[list[str], list[str]]:
    paths = [p.lower() for p in paths]
    calls = {name for key, name in CALL_APPS.items() if any(key in p for p in paths)}
    remote = {name for key, name in REMOTE_ACCESS.items() if any(key in p for p in paths)}
    return sorted(calls), sorted(remote)


class _Address(ctypes.Structure):
    _fields_ = [("selector", ctypes.c_uint32), ("scope", ctypes.c_uint32), ("element", ctypes.c_uint32)]


def _audio_u32(core_audio: ctypes.CDLL, obj: int, selector: bytes) -> int:
    addr = _Address(int.from_bytes(selector, "big"), int.from_bytes(b"glob", "big"), 0)
    out, size = ctypes.c_uint32(0), ctypes.c_uint32(4)
    core_audio.AudioObjectGetPropertyData(obj, ctypes.byref(addr), 0, None, ctypes.byref(size), ctypes.byref(out))
    return out.value


def microphone_in_use() -> bool:
    """Whether any app is using the default microphone. Reads the device's state, not its audio."""
    core_audio = ctypes.CDLL(ctypes.util.find_library("CoreAudio"))
    device = _audio_u32(core_audio, 1, b"dIn ")               # system object -> default input device
    return bool(device) and bool(_audio_u32(core_audio, device, b"gone"))   # running somewhere?


def latest_caller() -> str | None:
    """Best effort: the newest entry in the Mac's call history (needs Full Disk Access)."""
    try:
        db = sqlite3.connect(f"file:{CALL_HISTORY}?mode=ro", uri=True)
        row = db.execute("SELECT ZNAME, ZADDRESS FROM ZCALLRECORD ORDER BY ZDATE DESC LIMIT 1").fetchone()
    except sqlite3.Error:
        return None
    if not row:
        return None
    name, number = row
    digits = "".join(ch for ch in str(number or "") if ch.isdigit())
    return name or (f"Caller ending {digits[-4:]}" if digits else None)


def sense(pretend: list[str] | None) -> dict:
    if pretend is not None:
        names = {n.lower(): n for n in [*CALL_APPS.values(), *REMOTE_ACCESS.values()]}
        picked = [names[p] for p in pretend if p in names]
        calls = [p for p in picked if p in CALL_APPS.values()]
        return {"call_app": calls[0] if calls else None,
                "remote_access": [p for p in picked if p in REMOTE_ACCESS.values()]}
    ps = subprocess.run(["ps", "-axo", "comm="], capture_output=True, text=True).stdout.splitlines()
    calls, remote = running_apps(ps)
    return {"call_app": calls[0] if calls and microphone_in_use() else None, "remote_access": remote}


def describe(state: dict) -> str:
    call = (f"{state['call_app']} call live" + (f" with {state['caller']}" if state.get("caller") else "")
            if state["call_app"] else "no call")
    remote = (", ".join(state["remote_access"]) + " running") if state["remote_access"] else "no remote-control apps"
    return f"{call} · {remote}"


def _build(src: Path, out: Path) -> bool:
    """Compile a Swift helper once (and again when its source changes)."""
    if out.exists() and out.stat().st_mtime >= src.stat().st_mtime:
        return True
    print(f"Building {src.name} (one time)…")
    try:
        r = subprocess.run(["swiftc", "-O", str(src), "-o", str(out)], capture_output=True, text=True)
    except FileNotFoundError:
        print("swiftc not found (install Xcode Command Line Tools with `xcode-select --install`).")
        return False
    if r.returncode:
        print("Couldn't build it:\n" + r.stderr[-800:])
    return r.returncode == 0


def build_warning_window() -> bool:
    """The capture-proof alert window. Without it, alerts stay in the web page."""
    return _build(MACOS / "Warning.swift", WARNING_BIN)


def build_listener() -> bool:
    """The listener is an .app: macOS only honours its permission strings inside a bundle."""
    contents = LISTEN_APP / "Contents"
    (contents / "MacOS").mkdir(parents=True, exist_ok=True)
    shutil.copy(MACOS / "Listen-Info.plist", contents / "Info.plist")
    built = _build(MACOS / "Listen.swift", contents / "MacOS" / "listen")
    if built:
        subprocess.run(["codesign", "--force", "--sign", "-", str(LISTEN_APP)], capture_output=True)
    return built


def daemon(path: str, body: dict | None = None):
    req = urllib.request.Request(DAEMON + path, data=None if body is None else json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read())


def play_script(path: Path, stop: threading.Event) -> None:
    """The demo's stand-in for listening: one line every 6 s, as if heard on the call."""
    for i, line in enumerate(l.strip() for l in path.read_text().splitlines()):
        if stop.wait(6):
            return
        if not line:
            continue
        try:
            daemon("/calls/transcript", {"chunk": 1000 + i, "text": line})
            print(f"  heard: {line}")
        except OSError:
            pass


def main() -> None:
    parser = argparse.ArgumentParser(description="ElderShield device sensor for macOS")
    parser.add_argument("--pretend", help="report these instead of sensing, e.g. facetime,anydesk")
    parser.add_argument("--caller", help="who the call is with, if the call history can't say (demo)")
    parser.add_argument("--script", type=Path, help="lines to play as if heard on the call (demo)")
    parser.add_argument("--listen", action="store_true", help="listen to calls on this Mac (opt-in)")
    parser.add_argument("--allow-cloud", action="store_true",
                        help="with --listen: if the on-device speech model is missing, let Apple's servers transcribe")
    parser.add_argument("--speak", action="store_true", help="also say alerts aloud (headphones only)")
    args = parser.parse_args()
    if sys.platform != "darwin":
        raise SystemExit("device_watch.py runs on macOS.")
    sys.stdout.reconfigure(line_buffering=True)        # status lines show up even when logged to a file

    private_window = build_warning_window()
    listener = args.listen and build_listener()
    pretend = [p.strip().lower() for p in args.pretend.split(",")] if args.pretend else None
    print("ElderShield device sensor running" + (" (pretend mode)" if pretend is not None else "")
          + (", listening to calls" if listener else "") + ".")
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))   # so the cleanup below runs on `kill` too
    try:
        watch(args, pretend, private_window, listener)
    except KeyboardInterrupt:
        pass
    finally:
        if listener:                     # never leave the listener running after the sensor stops
            subprocess.run(["pkill", "-f", str(LISTEN_APP / "Contents/MacOS/listen")])


def listener_hearing() -> str | None:
    """What's wrong with the listener, from its log, or None if it is tapping audio and transcribing."""
    try:
        log = (MACOS / "listen.log").read_text()
    except OSError:
        return "the listener didn't start (no listen.log)"
    if "✓ tapping system audio" not in log:
        return "no system-audio permission: System Settings → Privacy & Security → Screen & System Audio Recording → ElderShield listener"
    if "transcribed" not in log:
        return "speech recognition not allowed or the on-device model is missing (see macos/listen.log)"
    return None


def watch(args, pretend, private_window: bool, listener: bool) -> None:
    last_alert, last_state, reachable, caller = time.time(), None, None, None
    window = None
    script_stop = threading.Event()
    call_started_at, listener_checked = None, False
    while True:
        try:
            state = sense(pretend)
            started = state["call_app"] and not (last_state or {}).get("call_app")
            ended = not state["call_app"] and (last_state or {}).get("call_app")
            if started:
                caller = args.caller or latest_caller()
                call_started_at, listener_checked = time.time(), False
                if listener:
                    (MACOS / "listen.log").unlink(missing_ok=True)
                    subprocess.run(["open", "-n", str(LISTEN_APP), "--args", "--post", DAEMON + "/calls/transcript",
                                    "--log", str(MACOS / "listen.log"), *(["--allow-cloud"] if args.allow_cloud else [])])
            elif state["call_app"] and not args.caller and time.time() - call_started_at < 30:
                # the Mac writes the call to its history a moment after it connects: keep looking early on
                found = latest_caller()
                if found and found != caller:
                    caller = found
                    print(f"  the call is with {caller}")
            if state["call_app"] and not listener_checked and time.time() - call_started_at >= 10 and (listener or args.script):
                listener_checked = True                # ten seconds in, the listener must be hearing the call
                if listener:
                    problem = listener_hearing()
                    print(f"  listener: {'hearing the call' if not problem else 'NOT HEARING THE CALL: ' + problem}")
                if args.script:
                    script_stop.clear()
                    threading.Thread(target=play_script, args=(args.script, script_stop), daemon=True).start()
            if ended:
                caller = None
                script_stop.set()
                if listener:
                    subprocess.run(["pkill", "-f", str(LISTEN_APP / "Contents/MacOS/listen")])
            state["caller"] = caller if state["call_app"] else None
            daemon("/device/context", {**state, "private_window": private_window})
            pending = daemon(f"/device/alerts?after={last_alert}")   # newest first
            if pending:
                alert = pending[-1]              # the oldest unseen one; the next tick shows the next
                last_alert = alert["ts"]
                if private_window:
                    if window and window.poll() is None:
                        window.terminate()                       # one alert on screen at a time
                    window = subprocess.Popen([str(WARNING_BIN), alert["title"], alert["body"]],
                                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if args.speak:
                    subprocess.Popen(["say", f"This is ElderShield. {alert['title']}"], stdout=subprocess.DEVNULL)
            if state != last_state:
                print(describe(state))
            last_state = state
            if reachable is False:
                print("ElderShield is reachable again.")
            reachable = True
        except OSError as e:                    # the daemon isn't running (URLError is an OSError)
            if reachable is not False:
                print(f"ElderShield isn't reachable ({e}); retrying every 2 s.")
            reachable = False
        time.sleep(2)


if __name__ == "__main__":
    main()
