"""
ElderShield — a payment guardian with a memory
==============================================

A local daemon that sits between an older adult and their bank. `device_watch.py` tells it
what is happening on this Mac (a live call and who with, a remote-control app) and, if
listening is switched on, what is being asked on the call. ElderShield keeps a journal of
calls and the warning signs heard in them, tracks each caller over weeks (the slow pattern of
a romance or investment scam), and when the senior tries to send money it pauses the payment
with a plain-language alert if the moment or the history calls for it.

Everything runs and is stored on this computer. The daemon answers only its own page.

Run:
    pip install -r requirements.txt
    python server.py                 # then open http://127.0.0.1:8777
    python device_watch.py           # second terminal
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any, Optional

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

HERE = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("ELDERSHIELD_DB", HERE / "eldershield_state.db"))
INDEX_PATH = HERE / "index.html"
PORT = 8777

# Only the daemon's own page (and an allowlisted extension origin, if configured) may call it.
# The Host check stops DNS-rebinding pages that resolve their own name to 127.0.0.1.
ALLOWED_HOSTS = {f"127.0.0.1:{PORT}", f"localhost:{PORT}"}
EXTENSION_ORIGINS = {o for o in os.environ.get("ELDERSHIELD_ALLOWED_ORIGINS", "").split(",") if o}
ALLOWED_ORIGINS = {f"http://{h}" for h in ALLOWED_HOSTS} | EXTENSION_ORIGINS

KEEP_SNIPPETS = os.environ.get("ELDERSHIELD_SNIPPETS", "1") != "0"   # the flagged sentence, for her record
DEVICE_REPORT_TTL_S = 6                          # the sensor reports every 2 s
REMOTE_ACCESS_MEMORY_S = 24 * 3600               # scammers often disconnect just before the transfer
OVERRIDE_WINDOW_S = 15 * 60                      # how long a "Send anyway" release stays usable
HISTORY_DAYS = 90                                # how far back the memory looks
RECENT_ASK_S = 24 * 3600                         # "asked you for money on a call" counts for a day

DAY = 86400

# Score components. ≥70 pauses with the stall (INTERCEPT); 40–69 pauses (CHALLENGE); <40 sends.
ACTION_RISK = {"wire_transfer": 20, "crypto_purchase": 20, "investment_deposit": 20, "gift_card_checkout": 18}
WEIGHTS = {
    "new_payee": 10,
    "live_call": 15,
    "remote_access": 35,              # someone else may be holding the mouse; with a call this alone intercepts
    "remote_access_earlier": 15,
    "money_asked_on_call": 35,        # money, gift cards or crypto came up on a call in the last day
    "pattern_isolating": 15,          # a caller's history, by how far their pattern has got
    "pattern_asking": 30,
    "pattern_escalating": 40,
}

# --------------------------------------------------------------------------- #
# Small utilities
# --------------------------------------------------------------------------- #


def now_ts() -> float:
    return time.time()


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _device_salt() -> bytes:
    path = HERE / "device.salt"
    if path.exists():
        return path.read_bytes()
    salt = os.urandom(16)
    path.write_bytes(salt)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return salt


_SALT = _device_salt()


def salted_hash(raw: str) -> str:
    """One-way and per-device: payment details and caller numbers are keyed this way."""
    return hashlib.sha256(_SALT + raw.strip().lower().encode()).hexdigest()[:24]


def ago(seconds: float) -> str:
    n, unit = ((max(1, int(seconds // 60)), "minute") if seconds < 3600 else
               (int(seconds // 3600), "hour") if seconds < DAY else (int(seconds // DAY), "day"))
    return f"{n} {unit}{'s' * (n > 1)} ago"


# --------------------------------------------------------------------------- #
# What was said: labels for a piece of call transcript
# --------------------------------------------------------------------------- #

# Each label: (phrases, confidence). The rules are the floor; a model such as Jev can replace
# classify() later and return the same shape with calibrated confidences.
LEXICON: dict[str, tuple[list[str], float]] = {
    "endearment": (["my love", "darling", "sweetheart", "my dear", "soulmate", "soul mate", "my queen",
                    "my king", "i love you", "love of my life", "falling for you", "my angel"], 0.8),
    "future_faking": (["when we meet", "marry you", "our future", "spend my life", "move in together",
                       "come and visit you", "fly to you", "our life together"], 0.8),
    "avoids_meeting": (["camera is broken", "camera broke", "can't video", "cannot video", "can't do video",
                        "oil rig", "deployed", "military base", "offshore", "account is frozen",
                        "can't meet", "cannot meet"], 0.8),
    "isolation_secrecy": (["don't tell", "do not tell", "keep this between us", "our secret",
                           "wouldn't understand", "they don't need to know", "keep it quiet"], 0.9),
    "money_request": (["send money", "send me", "wire", "western union", "pay the fee", "customs",
                       "hospital", "plane ticket", "flight ticket", "lend me", "loan me", "need money",
                       "pay you back", "release the package", "transfer the money", "dollars"], 0.7),
    "gift_cards": (["gift card", "itunes card", "apple card", "google play card", "steam card",
                    "read me the numbers"], 0.95),
    "crypto_investment": (["bitcoin", "crypto", "usdt", "trading platform", "guaranteed return",
                           "double your money", "investment opportunity"], 0.85),
    "remote_access": (["anydesk", "teamviewer", "remote access", "install this app", "download this app",
                       "share your screen", "screen share"], 0.9),
    "one_time_code": (["verification code", "the code we sent", "read me the code", "one-time code",
                       "six-digit code", "the code you just got"], 0.95),
    "threat_urgency": (["arrested", "warrant", "account will be frozen", "last chance", "right now",
                        "immediately"], 0.6),
}

ASK_LABELS = {"money_request", "gift_cards", "crypto_investment"}

# Said aloud, these get an alert during the call. Fixed wording: nothing the caller says can end
# up in the senior's warning.
LIVE_ALERTS = {
    "gift_cards": "Gift cards are always a scam. No real company, agency or loved one asks for them.",
    "one_time_code": "Never share that code. It lets someone into your account.",
    "remote_access": "Don't install anything they ask for. It lets them control your computer.",
    "money_request": "They just asked you for money. You don't have to decide on this call.",
    "crypto_investment": "Promises about crypto or guaranteed returns are how investment scams start.",
    "isolation_secrecy": "Someone who cares about you won't ask you to keep secrets from your family.",
}

LABEL_WORDS = {
    "endearment": "loving words", "future_faking": "promises about a future together",
    "avoids_meeting": "excuses not to meet or video call", "isolation_secrecy": "asked to keep it secret",
    "money_request": "asked for money", "gift_cards": "asked for gift cards",
    "crypto_investment": "talked about crypto or investing", "remote_access": "asked to install remote control",
    "one_time_code": "asked for a code", "threat_urgency": "pressure or threats",
}


def classify(text: str) -> list[tuple[str, float, int]]:
    """Labels in this text: (label, confidence, position of the match)."""
    low = text.lower()
    found = []
    for label, (phrases, conf) in LEXICON.items():
        for p in phrases:
            m = re.search(r"\b" + re.escape(p) + r"s?\b", low)
            if m:
                found.append((label, conf, m.start()))
                break
    return found


def snippet_around(text: str, pos: int) -> str:
    """The sentence around a match, short, with long numbers (codes, accounts) removed."""
    start = max(text.rfind(".", 0, pos), text.rfind("?", 0, pos), text.rfind("!", 0, pos)) + 1
    ends = [i for i in (text.find(c, pos) for c in ".?!") if i != -1]
    s = text[start:(min(ends) + 1 if ends else len(text))].strip()
    if len(s) > 140:                     # live speech has no punctuation: keep a window around the match
        lo = max(0, pos - start - 60)
        cut = s[lo:lo + 140]
        s = ("…" + cut.split(" ", 1)[-1] if lo else cut)
        if lo + 140 < len(text) - start:
            s = s.rsplit(" ", 1)[0] + "…"
    return re.sub(r"\d[\d\s-]{4,}\d", "[number]", s)


# --------------------------------------------------------------------------- #
# State: device, journal, payments, releases
# --------------------------------------------------------------------------- #


class Store:
    def __init__(self, db_path: Path = DB_PATH):
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS contacts (id TEXT PRIMARY KEY, label TEXT NOT NULL, first_seen REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS calls (
                id TEXT PRIMARY KEY, contact_id TEXT NOT NULL, app TEXT NOT NULL,
                started REAL NOT NULL, ended REAL, remote_access TEXT NOT NULL DEFAULT '[]');
            CREATE TABLE IF NOT EXISTS signals (
                id INTEGER PRIMARY KEY AUTOINCREMENT, call_id TEXT NOT NULL, contact_id TEXT NOT NULL,
                ts REAL NOT NULL, label TEXT NOT NULL, confidence REAL NOT NULL, snippet TEXT);
            CREATE TABLE IF NOT EXISTS remote_access_seen (name TEXT PRIMARY KEY, last_seen REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS payments (
                action_id TEXT PRIMARY KEY, ts REAL NOT NULL, fingerprint TEXT NOT NULL, action_type TEXT NOT NULL,
                amount REAL, decision TEXT NOT NULL, score INTEGER NOT NULL, call_id TEXT, released_by TEXT);
            CREATE TABLE IF NOT EXISTS overrides (
                token TEXT PRIMARY KEY, action_id TEXT NOT NULL, fingerprint TEXT NOT NULL,
                decision TEXT NOT NULL, created_at REAL NOT NULL, expires_at REAL NOT NULL, used_at REAL);
            CREATE INDEX IF NOT EXISTS ix_calls_contact ON calls(contact_id, started);
            CREATE INDEX IF NOT EXISTS ix_signals_contact ON signals(contact_id, ts);
        """)
        self.conn.commit()
        self._lock = Lock()
        self.report: dict[str, Any] = {}
        self.reported_at = 0.0
        self.alert: Optional[dict[str, Any]] = None   # the latest private alert; the sensor shows each new one
        self._heard: dict[tuple[str, int, str], int] = {}  # (call, chunk, label) -> its signal row
        self._alerted: set[tuple[str, str]] = set()     # (call, label) already alerted

    # -- device and calls ----------------------------------------------------
    def update_device(self, report: dict[str, Any]) -> None:
        now = now_ts()
        with self._lock:
            self.report, self.reported_at = report, now
            for name in report["remote_access"]:
                self.conn.execute("INSERT OR REPLACE INTO remote_access_seen VALUES (?, ?)", (name, now))
            self._sync_call(report, now)
            self.conn.commit()

    def _sync_call(self, report: dict[str, Any], at: float) -> None:
        """Open a journal entry when a call starts, close it when it ends (lock held)."""
        open_call = self.conn.execute("SELECT * FROM calls WHERE ended IS NULL").fetchone()
        if report.get("call_app") and not open_call:
            contact = self._contact(report.get("caller"), at)
            self.conn.execute("INSERT INTO calls VALUES (?,?,?,?,NULL,?)",
                              ("call_" + uuid.uuid4().hex[:10], contact, report["call_app"], at,
                               json.dumps(report["remote_access"])))
        elif open_call and not report.get("call_app"):
            self.conn.execute("UPDATE calls SET ended=? WHERE id=?", (at, open_call["id"]))
        elif open_call and report["remote_access"]:
            seen = sorted(set(json.loads(open_call["remote_access"])) | set(report["remote_access"]))
            self.conn.execute("UPDATE calls SET remote_access=? WHERE id=?", (json.dumps(seen), open_call["id"]))

    def _contact(self, caller: Optional[str], at: float) -> str:
        cid = salted_hash(caller) if caller else "unknown"
        self.conn.execute("INSERT OR IGNORE INTO contacts VALUES (?,?,?)", (cid, caller or "Unknown caller", at))
        return cid

    def device(self) -> dict[str, Any]:
        """Reports expire, so a sensor that stops reporting never leaves a stale 'call live' behind."""
        now = now_ts()
        with self._lock:
            live = self.report if now - self.reported_at < DEVICE_REPORT_TTL_S else {}
            if not live and self.reported_at:                 # sensor went quiet: end any open call
                self._sync_call({"call_app": None, "remote_access": []}, self.reported_at)
                self.conn.commit()
            seen = [r[0] for r in self.conn.execute(
                "SELECT name FROM remote_access_seen WHERE last_seen >= ? ORDER BY name",
                (now - REMOTE_ACCESS_MEMORY_S,))]
        running = live.get("remote_access", [])
        return {
            "sensor_live": bool(live),
            "call_app": live.get("call_app"),
            "caller": live.get("caller") if live.get("call_app") else None,
            "remote_access": running,
            "remote_access_earlier": [n for n in seen if n not in running],
            "private_window": bool(live.get("private_window")),
        }

    def current_call(self) -> Optional[dict[str, Any]]:
        row = self.conn.execute("SELECT * FROM calls WHERE ended IS NULL").fetchone()
        return dict(row) if row else None

    # -- what was heard --------------------------------------------------------
    def hear(self, chunk: int, text: str) -> list[dict[str, Any]]:
        """Store new labels heard on the current call; returns them."""
        call = self.current_call()
        if not call:
            return []
        new = []
        with self._lock:
            for label, conf, pos in classify(text):
                key = (call["id"], chunk, label)
                snippet = snippet_around(text, pos) if KEEP_SNIPPETS else None
                if key in self._heard:          # the same chunk again, usually more of the sentence
                    self.conn.execute("UPDATE signals SET snippet=? WHERE id=?", (snippet, self._heard[key]))
                    continue
                cur = self.conn.execute("INSERT INTO signals (call_id, contact_id, ts, label, confidence, snippet) "
                                        "VALUES (?,?,?,?,?,?)", (call["id"], call["contact_id"], now_ts(), label, conf, snippet))
                self._heard[key] = cur.lastrowid
                new.append({"label": label, "confidence": conf, "snippet": snippet,
                            "alert": (call["id"], label) not in self._alerted and label in LIVE_ALERTS})
                self._alerted.add((call["id"], label))
            self.conn.commit()
        return new

    # -- private alerts ------------------------------------------------------
    def push_alert(self, title: str, body: str) -> None:
        with self._lock:
            self.alert = {"ts": now_ts(), "title": title, "body": body}

    def alert_after(self, after: float) -> list[dict[str, Any]]:
        """Timestamps, not ids, so a daemon restart can't strand the sensor's cursor; and only
        recent ones, so a sensor that starts late doesn't pop up yesterday's warning."""
        with self._lock:
            a = self.alert
        return [a] if a and a["ts"] > after and a["ts"] > now_ts() - 30 else []

    # -- payments and releases -----------------------------------------------
    def record_payment(self, action_id: str, fingerprint: str, action_type: str, amount: Optional[float],
                       decision: str, score: int, released_by: Optional[str] = None) -> None:
        call = self.current_call()
        with self._lock:
            self.conn.execute("INSERT INTO payments VALUES (?,?,?,?,?,?,?,?,?)",
                              (action_id, now_ts(), fingerprint, action_type, amount, decision, score,
                               call["id"] if call else None, released_by))
            self.conn.commit()

    def payment(self, action_id: str) -> Optional[dict[str, Any]]:
        row = self.conn.execute("SELECT * FROM payments WHERE action_id=?", (action_id,)).fetchone()
        return dict(row) if row else None

    def add_override(self, token: str, action_id: str, fingerprint: str, decision: str) -> float:
        now = now_ts()
        with self._lock:
            self.conn.execute("INSERT INTO overrides VALUES (?,?,?,?,?,?,NULL)",
                              (token, action_id, fingerprint, decision, now, now + OVERRIDE_WINDOW_S))
            self.conn.commit()
        return now + OVERRIDE_WINDOW_S

    def take_override(self, token: str, fingerprint: str) -> Optional[dict[str, Any]]:
        """Single use, bound to one exact payment, and only within its window."""
        now = now_ts()
        with self._lock:
            cur = self.conn.execute(
                "UPDATE overrides SET used_at=? WHERE token=? AND fingerprint=? AND used_at IS NULL AND expires_at > ?",
                (now, token, fingerprint, now))
            self.conn.commit()
            if not cur.rowcount:
                return None
            return dict(self.conn.execute("SELECT * FROM overrides WHERE token=?", (token,)).fetchone())

    def clear(self) -> None:
        with self._lock:
            for table in ("contacts", "calls", "signals", "remote_access_seen", "payments", "overrides"):
                self.conn.execute(f"DELETE FROM {table}")
            self.conn.commit()
            self.alert = None
            self._heard.clear()
            self._alerted.clear()


# --------------------------------------------------------------------------- #
# The track: what the journal says about each caller, and about her week
# --------------------------------------------------------------------------- #

STAGES = ["", "no warning signs", "love-bombing", "isolating you", "asking for money", "escalating"]


def _minutes(call: sqlite3.Row, now: float) -> float:
    return ((call["ended"] or now) - call["started"]) / 60


def _late(ts: float) -> bool:
    h = datetime.fromtimestamp(ts).hour
    return h >= 22 or h < 6


def contact_track(store: Store, contact: sqlite3.Row, now: float) -> dict[str, Any]:
    since = now - HISTORY_DAYS * DAY
    calls = store.conn.execute("SELECT * FROM calls WHERE contact_id=? AND started>=? ORDER BY started",
                               (contact["id"], since)).fetchall()
    sigs = store.conn.execute("SELECT * FROM signals WHERE contact_id=? AND ts>=? ORDER BY ts",
                              (contact["id"], since)).fetchall()
    days_known = max(0, int((now - contact["first_seen"]) // DAY))
    week = [c for c in calls if c["started"] >= now - 7 * DAY]
    prev = [c for c in calls if now - 14 * DAY <= c["started"] < now - 7 * DAY]
    avg = lambda cs: round(sum(_minutes(c, now) for c in cs) / len(cs)) if cs else 0
    labels = {s["label"] for s in sigs}
    ask_days = {int(s["ts"] // DAY) for s in sigs if s["label"] in ASK_LABELS}
    first_ask = min((s["ts"] for s in sigs if s["label"] in ASK_LABELS), default=None)
    paid_after_ask = first_ask is not None and store.conn.execute(
        "SELECT COUNT(*) FROM payments WHERE ts>=?", (first_ask,)).fetchone()[0] > 0
    love = [s["ts"] for s in sigs if s["label"] == "endearment"]

    stage = 1 if calls else 0
    if love and (days_known <= 30 or len(week) >= 4):
        stage = 2
    if labels & {"isolation_secrecy", "avoids_meeting"}:
        stage = max(stage, 3)
    if labels & ASK_LABELS:
        stage = max(stage, 4)
    if len(ask_days) >= 2 or (stage >= 4 and paid_after_ask):
        stage = 5
    if contact["id"] == "unknown":
        stage = min(stage, 1)                   # many different callers: no single story to track

    name = contact["label"]
    flags = []
    if days_known <= 60 and len(week) >= 4:
        flags.append(f"Known for only {days_known} days, and called {len(week)} times this week")
    if love and love[0] - contact["first_seen"] <= 7 * DAY:
        d = int((love[0] - contact["first_seen"]) // DAY)
        flags.append("Used loving words " + ("on the first day" if d < 1 else f"within {d + 1} days") + " of first contact")
    if week and prev and avg(week) >= 1.5 * avg(prev):
        flags.append(f"Calls are getting longer: {avg(week)} minutes on average this week, {avg(prev)} the week before")
    late = sum(1 for c in week if _late(c["started"]))
    if late >= 2:
        flags.append(f"{late} calls late at night this week")
    excuses = sum(1 for s in sigs if s["label"] == "avoids_meeting")
    if excuses:
        flags.append(f"Has made {excuses} excuse{'s' * (excuses > 1)} not to meet or video call")
    if "isolation_secrecy" in labels:
        flags.append("Asked you to keep things from your family")
    if ask_days:
        flags.append(f"Asked for money on {len(ask_days)} different day{'s' * (len(ask_days) > 1)}")
    if "crypto_investment" in labels:
        flags.append("Talked about crypto or investing")

    return {
        "id": contact["id"], "name": name, "days_known": days_known, "stage": stage,
        "stage_name": STAGES[stage], "risk": "high" if stage >= 4 else "watch" if stage >= 2 else "low",
        "calls": len(calls), "calls_this_week": len(week), "minutes_this_week": round(sum(_minutes(c, now) for c in week)),
        "per_day": [sum(1 for c in calls if now - (d + 1) * DAY <= c["started"] < now - d * DAY) for d in range(20, -1, -1)],
        "flags": flags,
    }


def track(store: Store) -> dict[str, Any]:
    now = now_ts()
    contacts = [contact_track(store, c, now) for c in store.conn.execute("SELECT * FROM contacts").fetchall()]
    contacts = [c for c in contacts if c["calls"]]
    contacts.sort(key=lambda c: (-c["stage"], -c["calls_this_week"]))
    names = {c["id"]: c["name"] for c in contacts}

    recent = []
    for call in store.conn.execute("SELECT * FROM calls ORDER BY started DESC LIMIT 12").fetchall():
        sigs = store.conn.execute("SELECT label, snippet FROM signals WHERE call_id=? ORDER BY ts", (call["id"],)).fetchall()
        paid = store.conn.execute("SELECT amount, decision FROM payments WHERE call_id=?", (call["id"],)).fetchall()
        recent.append({
            "id": call["id"], "who": names.get(call["contact_id"], "Unknown caller"), "app": call["app"],
            "started": iso(call["started"]), "live": call["ended"] is None, "minutes": round(_minutes(call, now)),
            "late": _late(call["started"]), "remote_access": json.loads(call["remote_access"]),
            "heard": [{"label": s["label"], "words": LABEL_WORDS[s["label"]], "snippet": s["snippet"]} for s in sigs],
            "payments": [dict(p) for p in paid],
        })

    # Her own week against her usual, so a change in behaviour shows even before anyone asks.
    weeks = [store.conn.execute("SELECT COUNT(*) FROM calls WHERE started>=? AND started<?",
                                (now - (w + 1) * 7 * DAY, now - w * 7 * DAY)).fetchone()[0] for w in range(5)]
    usual = sum(weeks[1:]) / 4
    you = {"calls_this_week": weeks[0], "usual_calls_per_week": round(usual, 1),
           "change": (f"{weeks[0]} calls this week; usually about {round(usual)}" if usual and weeks[0] >= 2 * usual
                      else None)}
    return {"contacts": contacts, "recent_calls": recent, "you": you}


def memory_for_payment(store: Store) -> tuple[dict[str, int], list[str]]:
    """What the journal adds to a payment: a recent ask on a call, and any caller's long pattern."""
    now = now_ts()
    comp, reasons = {}, []
    ask = store.conn.execute(
        "SELECT s.ts, s.label, c.label AS who FROM signals s JOIN contacts c ON c.id=s.contact_id "
        f"WHERE s.ts>=? AND s.label IN ({','.join('?' * len(ASK_LABELS))}) ORDER BY s.ts DESC LIMIT 1",
        (now - RECENT_ASK_S, *sorted(ASK_LABELS))).fetchone()
    if ask:
        comp["money_asked_on_call"] = WEIGHTS["money_asked_on_call"]
        who = "someone" if ask["who"] == "Unknown caller" else ask["who"]
        reasons.append(f"{who} {LABEL_WORDS[ask['label']]} on a call {ago(now - ask['ts'])}")
    top = max((contact_track(store, c, now) for c in store.conn.execute("SELECT * FROM contacts").fetchall()),
              key=lambda t: t["stage"], default=None)
    if top and top["stage"] >= 3:
        key = {3: "pattern_isolating", 4: "pattern_asking", 5: "pattern_escalating"}[top["stage"]]
        comp["long_term_pattern"] = WEIGHTS[key]
        reasons.append(f"{top['name']}, someone you've known for {top['days_known']} days, has been "
                       + {3: "isolating you", 4: "asking you for money", 5: "asking for more and more money"}[top["stage"]])
    return comp, reasons


# --------------------------------------------------------------------------- #
# Scoring — deterministic, fixed code, no model in the loop
# --------------------------------------------------------------------------- #


def decide(score: int) -> str:
    return "INTERCEPT" if score >= 70 else ("CHALLENGE" if score >= 40 else "ALLOW")


def score_payment(action_type: str, new_payee: bool, device: dict[str, Any],
                  memory: tuple[dict[str, int], list[str]]) -> dict[str, Any]:
    comp: dict[str, int] = {}
    reasons: list[str] = []
    if device["remote_access"]:
        comp["remote_access"] = WEIGHTS["remote_access"]
        reasons.append(f"a remote-control app ({', '.join(device['remote_access'])}) is running on this computer")
    elif device["remote_access_earlier"]:
        comp["remote_access_earlier"] = WEIGHTS["remote_access_earlier"]
        reasons.append(f"a remote-control app ({', '.join(device['remote_access_earlier'])}) "
                       "was running on this computer earlier today")
    if device["call_app"]:
        comp["live_call"] = WEIGHTS["live_call"]
        reasons.append(f"you're on a {device['call_app']} call" + (f" with {device['caller']}" if device["caller"] else "")
                       + " right now")
    comp.update(memory[0])
    reasons += memory[1]
    if not comp:                                   # nothing unusual now or in her history: send it
        return {"score": 0, "decision": "ALLOW", "components": {}, "reasons": []}
    comp["action_risk"] = ACTION_RISK.get(action_type, 5)
    if new_payee:
        comp["new_payee"] = WEIGHTS["new_payee"]
    score = min(100, sum(comp.values()))
    return {"score": score, "decision": decide(score), "components": comp, "reasons": reasons}


# --------------------------------------------------------------------------- #
# App
# --------------------------------------------------------------------------- #

app = FastAPI(title="ElderShield", version="4.0.0")
if EXTENSION_ORIGINS:
    app.add_middleware(CORSMiddleware, allow_origins=sorted(EXTENSION_ORIGINS),
                       allow_methods=["GET", "POST"], allow_headers=["Content-Type"])


@app.middleware("http")
async def local_ui_only(request: Request, call_next):
    # Browsers send Origin on every cross-site POST (including no-cors ones, which skip CORS
    # entirely), so this is what actually stops a web page from wiping or releasing anything.
    origin = request.headers.get("origin")
    if request.headers.get("host") not in ALLOWED_HOSTS or (origin and origin not in ALLOWED_ORIGINS):
        return JSONResponse({"error": "forbidden"}, status_code=403)
    return await call_next(request)


STORE = Store()


class ActionIn(BaseModel):
    origin: str
    action_type: str = "wire_transfer"
    amount: Optional[float] = None
    new_payee: bool = False
    routing_number: Optional[str] = None
    account_number: Optional[str] = None
    wallet_address: Optional[str] = None
    destination_domain: Optional[str] = None
    override_token: Optional[str] = None


class OverrideIn(BaseModel):
    action_id: str


class DeviceReport(BaseModel):
    call_app: Optional[str] = Field(None, max_length=40)       # set only while a call is live
    caller: Optional[str] = Field(None, max_length=80)          # from call history, or the demo
    remote_access: list[str] = Field(default_factory=list, max_length=10)
    private_window: bool = False                                # sensor can show the capture-proof alert


class TranscriptIn(BaseModel):
    chunk: int = 0                                              # the listener restarts recognition in chunks
    text: str = Field(max_length=5000)


def fingerprint(a: ActionIn) -> str:
    """Identifies 'this payment' across resubmits: same kind, place, amount and destination."""
    return salted_hash("|".join(str(v or "") for v in (
        a.action_type, a.origin, a.amount, a.routing_number, a.account_number,
        a.wallet_address, a.destination_domain)))


def build_decoy() -> dict[str, Any]:
    """What a screen-sharing onlooker sees: a believable stall that never completes."""
    return {"headline": "Verifying transaction details with receiving institution…",
            "subline": "Please keep this window open. This can take a few minutes.",
            "progress_start": 3, "progress_ceiling": 61, "tick_ms": 1400}


@app.get("/", response_class=HTMLResponse)
def ui() -> str:
    return INDEX_PATH.read_text()


@app.get("/health")
def health() -> dict[str, Any]:
    return {"ok": True, "version": "4.0.0"}


@app.post("/evaluate/action")
def evaluate_action(a: ActionIn) -> dict[str, Any]:
    t0 = time.perf_counter()
    action_id = "act_" + uuid.uuid4().hex[:10]
    fp = fingerprint(a)
    device = STORE.device()

    if a.override_token and STORE.take_override(a.override_token, fp):
        STORE.record_payment(action_id, fp, a.action_type, a.amount, "ALLOW", 0, released_by="senior")
        return {"action_id": action_id, "decision": "ALLOW", "score": 0, "components": {}, "reasons": [],
                "path": "override", "decoy": None, "private_overlay": False, "locked": False,
                "latency_ms": round((time.perf_counter() - t0) * 1000, 1)}

    s = score_payment(a.action_type, a.new_payee, device, memory_for_payment(STORE))
    paused = s["decision"] != "ALLOW"
    # The stall is for an onlooker; while someone may be watching, the truth goes to the window
    # screen sharing can't see and the page shows only the stall — whatever the risk level.
    watching = bool(device["call_app"] or device["remote_access"])
    decoy = build_decoy() if paused and watching else None
    private_overlay = decoy is not None and device["private_window"]
    # "Send anyway" waits while someone else may be holding the mouse, or while a high-risk
    # payment is being made during a call: a scammer's hold depends on staying on the line.
    locked = paused and (bool(device["remote_access"]) or (s["decision"] == "INTERCEPT" and watching))

    if private_overlay:
        amount = f" ${a.amount:,.0f}" if a.amount else " this payment"
        STORE.push_alert(f"Wait — before you send{amount}",
                         "\n".join(f"• {r[0].upper()}{r[1:]}" for r in s["reasons"])
                         + "\n\nIt's safe to hang up. The other person only sees a “processing” screen. "
                         + "When you've hung up, press the button on the bank page.")
    STORE.record_payment(action_id, fp, a.action_type, a.amount, s["decision"], s["score"])
    return {
        "action_id": action_id, "decision": s["decision"], "score": s["score"],
        "components": s["components"], "reasons": s["reasons"], "path": "memory" if paused else "none",
        "decoy": decoy, "private_overlay": private_overlay, "locked": locked,
        "latency_ms": round((time.perf_counter() - t0) * 1000, 1),
    }


@app.post("/override", response_model=None)
def create_override(o: OverrideIn) -> dict[str, Any] | JSONResponse:
    """"Send anyway" for one paused payment. Refused while a remote-control app is running
    (someone else may click it) and, for an INTERCEPT, while a call is live. The token works
    once, for that exact payment, and every release is recorded."""
    p = STORE.payment(o.action_id)
    if not p or p["decision"] == "ALLOW":
        return JSONResponse({"error": "no paused payment with that action_id"}, status_code=404)
    device = STORE.device()
    if device["remote_access"] or (p["decision"] == "INTERCEPT" and device["call_app"]):
        return JSONResponse({"error": "wait_until_nobody_is_watching", "call_app": device["call_app"],
                             "remote_access": device["remote_access"]}, status_code=409)
    token = "ovr_" + uuid.uuid4().hex
    expires = STORE.add_override(token, o.action_id, p["fingerprint"], p["decision"])
    return {"override_token": token, "status": "approved", "expires_at": iso(expires)}


@app.post("/device/context")
def device_context(r: DeviceReport) -> dict[str, Any]:
    """device_watch.py reports what it sees every couple of seconds."""
    STORE.update_device(r.model_dump())
    return {"ok": True}


@app.get("/device/alerts")
def device_alerts(after: float = 0) -> list[dict[str, Any]]:
    """Private alerts for device_watch.py to show in its capture-proof window."""
    return STORE.alert_after(after)


@app.post("/calls/transcript")
def call_transcript(t: TranscriptIn) -> dict[str, Any]:
    """The listener (or the demo script) sends what it hears on the current call. Only the
    labels and, if enabled, the flagged sentence are kept; the rest is dropped here."""
    heard = STORE.hear(t.chunk, t.text)
    for h in heard:
        if h["alert"]:
            call = STORE.current_call()
            who = STORE.conn.execute("SELECT label FROM contacts WHERE id=?", (call["contact_id"],)).fetchone()[0]
            STORE.push_alert(f"On this call: {LABEL_WORDS[h['label']]}",
                             LIVE_ALERTS[h["label"]] + ("" if who == "Unknown caller" else f"\n\n(The caller: {who}.)"))
    return {"heard": [{k: h[k] for k in ("label", "confidence", "snippet")} for h in heard]}


@app.get("/state")
def state() -> dict[str, Any]:
    return {"device": STORE.device(), "track": track(STORE), "alert": STORE.alert_after(0)}


@app.post("/reset")
def reset() -> dict[str, Any]:
    STORE.clear()
    return {"ok": True}


@app.post("/demo/seed")
def demo_seed() -> dict[str, Any]:
    """Three weeks of history for the demo: a romance scammer working up to money, a daughter
    who calls weekly, and one unknown caller."""
    import demo_history
    STORE.clear()
    demo_history.seed(STORE.conn, salted_hash, now_ts())
    return {"ok": True}


if __name__ == "__main__":
    import uvicorn

    print(f"ElderShield → http://127.0.0.1:{PORT}")
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning")
