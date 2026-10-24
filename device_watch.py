"""
Tells ElderShield what is happening on this Mac right now, and shows its private warnings.

  - A live call: FaceTime (which also carries iPhone calls on a Mac) or another call app is
    running while the microphone is in use.
  - Remote control: AnyDesk, TeamViewer and similar apps are running.

It reports to the daemon every 2 s. When the daemon intercepts a payment while someone may be
watching, the warning appears in a window that screen sharing and screen capture can't see
(macos/Warning.swift), so a scammer watching the shared screen sees only the "processing" stall.

    python device_watch.py                              # real sensors
    python device_watch.py --pretend facetime,anydesk   # rehearse the demo without a real call
    python device_watch.py --speak                      # also say warnings aloud (headphones only:
                                                        # on speaker the caller would hear it)

Needs no macOS permissions: it reads the process list and whether the microphone is in use,
never audio or screen contents.
"""

import argparse
import ctypes
import ctypes.util
import json
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

DAEMON = "http://127.0.0.1:8777"
HERE = Path(__file__).resolve().parent
WARNING_SRC = HERE / "macos" / "Warning.swift"
WARNING_BIN = HERE / "macos" / "eldershield-warning"

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
    call = f"{state['call_app']} call live" if state["call_app"] else "no call"
    remote = (", ".join(state["remote_access"]) + " running") if state["remote_access"] else "no remote-control apps"
    return f"{call} · {remote}"


def build_warning_window() -> bool:
    """Compiles the capture-proof warning window once. Without it, warnings stay in the web page,
    which screen sharing can see."""
    if WARNING_BIN.exists() and WARNING_BIN.stat().st_mtime >= WARNING_SRC.stat().st_mtime:
        return True
    print("Building the private warning window (one time)…")
    try:
        r = subprocess.run(["swiftc", "-O", str(WARNING_SRC), "-o", str(WARNING_BIN)], capture_output=True, text=True)
    except FileNotFoundError:
        print("swiftc not found (install Xcode Command Line Tools); warnings will stay in the page.")
        return False
    if r.returncode:
        print("Couldn't build it; warnings will stay in the page.\n" + r.stderr[-800:])
    return r.returncode == 0


def daemon(path: str, body: dict | None = None):
    req = urllib.request.Request(DAEMON + path, data=None if body is None else json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read())


def main() -> None:
    parser = argparse.ArgumentParser(description="ElderShield device sensor for macOS")
    parser.add_argument("--pretend", help="report these instead of sensing, e.g. facetime,anydesk")
    parser.add_argument("--speak", action="store_true", help="also say warnings aloud (headphones only)")
    args = parser.parse_args()
    if sys.platform != "darwin":
        raise SystemExit("device_watch.py runs on macOS.")
    sys.stdout.reconfigure(line_buffering=True)        # status lines show up even when logged to a file

    private_window = build_warning_window()
    pretend = [p.strip().lower() for p in args.pretend.split(",")] if args.pretend else None
    last_alert, last_state, reachable = 0, None, None
    print("ElderShield device sensor running" + (" (pretend mode)" if pretend is not None else "") + ".")
    while True:
        try:
            state = sense(pretend)
            daemon("/device/context", {**state, "private_window": private_window})
            for alert in daemon(f"/device/alerts?after={last_alert}"):
                last_alert = alert["id"]
                if private_window:
                    subprocess.Popen([str(WARNING_BIN), alert["title"], alert["body"]])
                if args.speak:
                    subprocess.Popen(["say", f"This is ElderShield. {alert['title']} It is safe to hang up."])
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
