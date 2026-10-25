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
import threading
from threading import Lock, Thread
from typing import Any, Optional

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

import jev

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
ASSESS_EVERY_S = float(os.environ.get("ELDERSHIELD_ASSESS_EVERY_S", "2"))   # Jev re-judges a live call this often

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

# Each label: (phrases, confidence). The rules are the floor and work offline; with a
# TYPESAFE_API_KEY, Jev (jev.py) also hears each finished sentence and adds the labels the rules
# miss, with a calibrated probability each.
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
    "remote_access": (["anydesk", "any desk", "teamviewer", "team viewer", "remote access", "install this app", "download this app",
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


def finished_sentences(text: str, final: bool = False) -> list[tuple[str, int]]:
    """Sentences in a transcript that are complete: (sentence, position). The listener sends a
    growing transcript every ~0.8 s; the sentence being spoken is still changing, so Jev waits
    for the one before it, unless the chunk is final, when the last one is finished too. If the
    recognizer gave no punctuation, a long run of words is cut into ~12-word pieces instead."""
    out, start = [], 0
    for m in re.finditer(r"[.?!]+(\s+|$)", text):
        out.append((text[start:m.end()].strip(), start))
        start = m.end()
    tail = text[start:].strip()
    words = tail.split()
    while len(words) > 24:                      # no punctuation: the first 12 words are settled
        piece = " ".join(words[:12])
        out.append((piece, text.find(piece, start)))
        start = text.find(piece, start) + len(piece)
        words = words[12:]
    if final and words:
        out.append((" ".join(words), text.find(words[0], start)))
    return [(s, p) for s, p in out if len(s.split()) >= 3]


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
                ts REAL NOT NULL, label TEXT NOT NULL, confidence REAL NOT NULL, snippet TEXT,
                source TEXT NOT NULL DEFAULT 'rules');
            CREATE TABLE IF NOT EXISTS remote_access_seen (name TEXT PRIMARY KEY, last_seen REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS payments (
                action_id TEXT PRIMARY KEY, ts REAL NOT NULL, fingerprint TEXT NOT NULL, action_type TEXT NOT NULL,
                amount REAL, decision TEXT NOT NULL, score INTEGER NOT NULL, call_id TEXT, released_by TEXT);
            CREATE TABLE IF NOT EXISTS assessments (
                id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, contact_id TEXT NOT NULL, call_id TEXT,
                fraud_likely REAL NOT NULL, financial_steering REAL NOT NULL, isolation REAL NOT NULL,
                escalation REAL NOT NULL, pattern TEXT NOT NULL, pattern_confidence REAL NOT NULL,
                evidence TEXT NOT NULL, model TEXT, ms INTEGER);
            CREATE INDEX IF NOT EXISTS ix_assess_contact ON assessments(contact_id, ts);
            CREATE TABLE IF NOT EXISTS overrides (
                token TEXT PRIMARY KEY, action_id TEXT NOT NULL, fingerprint TEXT NOT NULL,
                decision TEXT NOT NULL, created_at REAL NOT NULL, expires_at REAL NOT NULL, used_at REAL);
            CREATE INDEX IF NOT EXISTS ix_calls_contact ON calls(contact_id, started);
            CREATE INDEX IF NOT EXISTS ix_signals_contact ON signals(contact_id, ts);
        """)
        if "source" not in [r[1] for r in self.conn.execute("PRAGMA table_info(signals)")]:   # journals from before Jev
            self.conn.execute("ALTER TABLE signals ADD COLUMN source TEXT NOT NULL DEFAULT 'rules'")
        self.conn.commit()
        self._lock = Lock()
        self.report: dict[str, Any] = {}
        self.reported_at = 0.0
        self.alerts: list[dict[str, Any]] = []     # recent private alerts, newest first; the sensor shows each
        self._heard: dict[tuple[str, int, str], int] = {}  # (call, chunk, label) -> its signal row
        self._alerted: set[tuple[str, str]] = set()     # (call, label) already alerted
        self._asked_jev: set[tuple[str, str]] = set()   # (call, sentence) Jev has already been asked about

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
    def hear(self, chunk: int, text: str, final: bool = False) -> list[dict[str, Any]]:
        """Store the labels the rules hear in this transcript; returns the new ones. Finished
        sentences also go to Jev, whose labels arrive through hear_from_jev() a moment later."""
        call = self.current_call()
        if not call:
            return []
        new = self._record(call, chunk, text, classify(text))
        for sentence, pos in finished_sentences(text, final):
            key = (call["id"], sentence)
            if key in self._asked_jev:
                continue
            self._asked_jev.add(key)
            jev.classify_async(sentence, lambda labels, s=sentence, p=pos, c=chunk: self.hear_from_jev(call, c, s, labels))
        return new

    def hear_from_jev(self, call: dict[str, Any], chunk: int, sentence: str, labels: list[tuple[str, float]]) -> None:
        """Jev's labels for one sentence. The rules' row for the same label wins; Jev adds only
        what they missed, and raises the live alert for it like any other label."""
        found = [(label, prob, 0) for label, prob in labels]
        new = self._record(call, chunk, sentence, found, source="jev")
        for h in new:
            if h["alert"]:
                raise_live_alert(self, call, h["label"])
        if new:
            ASSESSOR.poke()

    def _record(self, call: dict[str, Any], chunk: int, text: str,
                found: list[tuple[str, float, int]], source: str = "rules") -> list[dict[str, Any]]:
        new = []
        with self._lock:
            for label, conf, pos in found:
                key = (call["id"], chunk, label)
                snippet = snippet_around(text, pos) if KEEP_SNIPPETS else None
                if key in self._heard:          # the same chunk again, usually more of the sentence
                    if source == "rules":
                        self.conn.execute("UPDATE signals SET snippet=? WHERE id=?", (snippet, self._heard[key]))
                    continue
                cur = self.conn.execute("INSERT INTO signals (call_id, contact_id, ts, label, confidence, snippet, source) "
                                        "VALUES (?,?,?,?,?,?,?)",
                                        (call["id"], call["contact_id"], now_ts(), label, conf, snippet, source))
                self._heard[key] = cur.lastrowid
                new.append({"label": label, "confidence": conf, "snippet": snippet, "source": source,
                            "alert": (call["id"], label) not in self._alerted and label in LIVE_ALERTS})
                self._alerted.add((call["id"], label))
            self.conn.commit()
        return new

    # -- private alerts ------------------------------------------------------
    def push_alert(self, title: str, body: str) -> None:
        with self._lock:
            self.alerts.insert(0, {"ts": now_ts(), "title": title, "body": body})
            del self.alerts[10:]

    def alert_after(self, after: float) -> list[dict[str, Any]]:
        """Alerts newer than the sensor's cursor, newest first. Timestamps, not ids, so a daemon
        restart can't strand the cursor; and only recent ones, so a sensor that starts late
        doesn't pop up yesterday's warning. A list, so two warning signs a second apart (the
        rule's alert, then Jev's) both reach her."""
        cutoff = max(after, now_ts() - 30)
        with self._lock:
            return [a for a in self.alerts if a["ts"] > cutoff]

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

    def add_assessment(self, contact_id: str, call_id: Optional[str], verdict: dict[str, Any], evidence: dict[str, Any]) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT INTO assessments (ts, contact_id, call_id, fraud_likely, financial_steering, isolation, escalation, "
                "pattern, pattern_confidence, evidence, model, ms) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (now_ts(), contact_id, call_id, verdict["fraud_likely"], verdict["financial_steering"], verdict["isolation"],
                 verdict["escalation"], verdict["pattern"], verdict["pattern_confidence"], json.dumps(evidence),
                 verdict.get("model"), verdict.get("ms")))
            self.conn.commit()

    def latest_assessment(self, contact_id: str) -> Optional[dict[str, Any]]:
        row = self.conn.execute("SELECT * FROM assessments WHERE contact_id=? ORDER BY ts DESC LIMIT 1", (contact_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["evidence"] = json.loads(d["evidence"])
        prev = self.conn.execute("SELECT fraud_likely FROM assessments WHERE contact_id=? AND ts<? ORDER BY ts DESC LIMIT 1",
                                 (contact_id, row["ts"])).fetchone()
        d["previous_fraud_likely"] = prev[0] if prev else None
        d["ago"] = ago(now_ts() - row["ts"])
        return d

    def clear(self) -> None:
        with self._lock:
            for table in ("contacts", "calls", "signals", "remote_access_seen", "payments", "overrides", "assessments"):
                self.conn.execute(f"DELETE FROM {table}")
            self.conn.commit()
            self.alerts.clear()
            self._heard.clear()
            self._alerted.clear()
            self._asked_jev.clear()


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

    verdict = store.latest_assessment(contact["id"])
    return {
        "jev": ({k: verdict[k] for k in ("fraud_likely", "financial_steering", "isolation", "escalation", "pattern",
                                          "pattern_confidence", "previous_fraud_likely", "ago", "ms")}
                | {"pattern_words": PATTERN_WORDS.get(verdict["pattern"], verdict["pattern"])}) if verdict else None,
        "id": contact["id"], "name": name, "days_known": days_known, "stage": stage,
        "stage_name": STAGES[stage],
        "risk": ("high" if stage >= 4 or (verdict and verdict["fraud_likely"] >= 0.7)
                 else "watch" if stage >= 2 or (verdict and verdict["fraud_likely"] >= 0.4) else "low"),
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
        sigs = store.conn.execute("SELECT label, snippet, source, confidence FROM signals WHERE call_id=? ORDER BY ts",
                                  (call["id"],)).fetchall()
        paid = store.conn.execute("SELECT amount, decision FROM payments WHERE call_id=?", (call["id"],)).fetchall()
        recent.append({
            "id": call["id"], "who": names.get(call["contact_id"], "Unknown caller"), "app": call["app"],
            "started": iso(call["started"]), "live": call["ended"] is None, "minutes": round(_minutes(call, now)),
            "late": _late(call["started"]), "remote_access": json.loads(call["remote_access"]),
            "heard": [{"label": s["label"], "words": LABEL_WORDS[s["label"]], "snippet": s["snippet"],
                       "source": s["source"], "confidence": s["confidence"]} for s in sigs],
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
    ladder = 0
    if top and top["stage"] >= 3:
        key = {3: "pattern_isolating", 4: "pattern_asking", 5: "pattern_escalating"}[top["stage"]]
        ladder = WEIGHTS[key]
        reasons.append(f"{top['name']}, someone you've known for {top['days_known']} days, has been "
                       + {3: "isolating you", 4: "asking you for money", 5: "asking for more and more money"}[top["stage"]])
    # Jev's judgment of the same history (layer 2): it sees the combination the ladder can't.
    # The ladder stays as the floor, so a Jev outage or a low reading never weakens the rules.
    judged = max((a for a in (store.latest_assessment(c["id"]) for c in store.conn.execute("SELECT id FROM contacts").fetchall())
                  if a and now - a["ts"] < HISTORY_DAYS * DAY), key=lambda a: a["fraud_likely"], default=None)
    jev_points = int(round(WEIGHTS["pattern_escalating"] * judged["fraud_likely"])) if judged and judged["fraud_likely"] >= 0.5 else 0
    if jev_points:
        comp["long_term_pattern"] = max(ladder, jev_points)   # the ladder is the floor
        who = store.conn.execute("SELECT label FROM contacts WHERE id=?", (judged["contact_id"],)).fetchone()[0]
        if ladder and top and top["name"] == who:            # Jev agrees with the ladder: one reason, Jev's wording
            reasons.pop()
        reasons.append(f"the pattern of calls with {who} looks like {PATTERN_WORDS.get(judged['pattern'], judged['pattern'])} "
                       f"({int(judged['fraud_likely'] * 100)}% sure)")
    elif ladder:
        comp["long_term_pattern"] = ladder
    return comp, reasons


# --------------------------------------------------------------------------- #
# Layer 2: Jev judges the live call against the caller's history, every few seconds
# --------------------------------------------------------------------------- #


def evidence_for(store: Store, contact: sqlite3.Row, now: float) -> dict[str, Any]:
    """What Jev sees: counts, labels and amounts from the journal. Never the words."""
    since = now - HISTORY_DAYS * DAY
    calls = store.conn.execute("SELECT * FROM calls WHERE contact_id=? AND started>=? ORDER BY started",
                               (contact["id"], since)).fetchall()
    week = [c for c in calls if c["started"] >= now - 7 * DAY]
    before = [c for c in calls if c["started"] < now - 7 * DAY]
    avg = lambda cs: round(sum(_minutes(c, now) for c in cs) / len(cs)) if cs else 0
    sigs = store.conn.execute("SELECT call_id, ts, label, snippet FROM signals WHERE contact_id=? AND ts>=? ORDER BY ts",
                              (contact["id"], since)).fetchall()
    amounts = []
    for sg in sigs:
        if sg["label"] in ASK_LABELS and sg["snippet"]:
            for m in re.findall(r"\$\s?(\d[\d,]*)|(\d[\d,]*)\s*(?:dollars|bucks)", sg["snippet"]):
                amounts.append(int((m[0] or m[1]).replace(",", "")))
    first_ask = min((sg["ts"] for sg in sigs if sg["label"] in ASK_LABELS), default=None)
    paid = [r[0] for r in store.conn.execute("SELECT amount FROM payments WHERE decision='ALLOW' AND ts>=?",
                                             (first_ask,)).fetchall()] if first_ask else []
    live = store.current_call()
    by_call: dict[str, list[str]] = {}
    for sg in sigs:
        by_call.setdefault(sg["call_id"], []).append(sg["label"])
    earlier = [{"days_ago": round((now - c["started"]) / DAY, 1), "minutes": round(_minutes(c, now)),
                "late_night": _late(c["started"]), "heard": by_call.get(c["id"], [])}
               for c in calls if not live or c["id"] != live["id"]][-12:]
    usual = store.conn.execute("SELECT COUNT(*) FROM calls WHERE started>=? AND started<?",
                               (now - 35 * DAY, now - 7 * DAY)).fetchone()[0] / 4
    return {
        "listener": "an older adult",
        "caller": {
            "known_for_days": max(0, int((now - contact["first_seen"]) // DAY)),
            "calls_total": len(calls), "calls_this_week": len(week),
            "avg_minutes_this_week": avg(week), "avg_minutes_before_this_week": avg(before),
            "late_night_calls_this_week": sum(1 for c in week if _late(c["started"])),
            "days_with_money_requests": len({int(sg["ts"] // DAY) for sg in sigs if sg["label"] in ASK_LABELS}),
            "amounts_asked_in_order": amounts,
            "payments_sent_after_first_request": [p for p in paid if p],
            "warning_signs_ever": sorted({sg["label"] for sg in sigs}),
        },
        "listener_usual": {"calls_per_week_from_everyone": round(usual, 1)},
        "this_call": ({"minutes_so_far": round(_minutes(live, now)), "heard_so_far": by_call.get(live["id"], []),
                       "remote_control_running": json.loads(live["remote_access"])}
                      if live and live["contact_id"] == contact["id"] else None),
        "earlier_calls": earlier,
    }


# What Jev's judgment says to her. Fixed wording keyed by level and pattern; the second line is
# built from the same evidence Jev was given, so the alert shows its reasons, not just a verdict.
VERDICT_ALERTS = {
    "high": {
        "romance": ("This call fits how romance scams work",
                    "Someone who truly cares about you won't rush you, hide from your family, or need your money."),
        "impersonation": ("This call fits how bank and tech-support scams work",
                          "A real bank or tech company never asks for remote access, codes, or urgent payments."),
        "investment": ("This call fits how investment scams work",
                       "Guaranteed returns don't exist. No one you've just met should be managing your money."),
        "family_emergency": ("This call fits how family-emergency scams work",
                             "Hang up and call that relative on the number you already have."),
        "none": ("This caller's behaviour is a serious concern",
                 "The pattern of these calls looks like manipulation, even if no single thing said was alarming."),
    },
    "watch": {
        "default": ("Something about these calls is concerning",
                    "Nothing has happened yet, but this is how manipulation usually starts. Take it slowly."),
    },
}


def verdict_alert(level: str, verdict: dict[str, Any], evidence: dict[str, Any], who: str) -> tuple[str, str]:
    """(title, body) for a layer-2 alert. The body's first sentence is the evidence, in her words."""
    c = evidence["caller"]
    name = "This caller" if who == "Unknown caller" else who
    facts = [f"{name} has known you {c['known_for_days']} days"]
    if c["calls_this_week"] >= 3:
        facts.append(f"called {c['calls_this_week']} times this week")
    if c["late_night_calls_this_week"] >= 2:
        facts.append("calls late at night")
    if "isolation_secrecy" in c["warning_signs_ever"]:
        facts.append("asked you to keep things from your family")
    if c["days_with_money_requests"]:
        facts.append(f"asked for money on {c['days_with_money_requests']} different day"
                     + ("s" if c["days_with_money_requests"] > 1 else ""))
    elif "crypto_investment" in c["warning_signs_ever"]:
        facts.append("talked about investing")
    if c["payments_sent_after_first_request"]:
        facts.append("already received money from you")
    title, advice = (VERDICT_ALERTS["high"].get(verdict["pattern"], VERDICT_ALERTS["high"]["none"]) if level == "high"
                     else VERDICT_ALERTS["watch"]["default"])
    pct = int(verdict["fraud_likely"] * 100)
    body = ", ".join(facts) + ". " + advice + f"\n\n(Jev's judgment of the whole pattern: {pct}% likely fraud. It's safe to hang up.)"
    return f"{title} ({pct}% sure)", body


class Assessor:
    """Runs Jev's call-level judgment every ASSESS_EVERY_S while a call is live, at once when a
    new warning sign lands (poke), and once more when the call ends."""

    def __init__(self, store: Store):
        self.store = store
        self._wake = threading.Event()
        self._last_call: Optional[str] = None
        self._alerted: set[tuple[str, str]] = set()     # (call, level) already shown
        Thread(target=self._loop, daemon=True).start()

    def poke(self) -> None:
        self._wake.set()

    def _loop(self) -> None:
        while True:
            self._wake.wait(ASSESS_EVERY_S)
            self._wake.clear()
            try:
                live = self.store.current_call()
                if live:
                    self._last_call = live["id"]
                    self.run(live["contact_id"], live["id"])
                elif self._last_call:                       # the call just ended: one final judgment
                    ended = self.store.conn.execute("SELECT contact_id FROM calls WHERE id=?", (self._last_call,)).fetchone()
                    self._last_call = None
                    if ended:
                        self.run(ended["contact_id"], None)
            except Exception as e:                          # never let the loop die
                jev.STATUS.last_error = f"assessor: {e}"[:160]

    def run(self, contact_id: str, call_id: Optional[str]) -> Optional[dict[str, Any]]:
        if not jev.enabled():
            return None
        contact = self.store.conn.execute("SELECT * FROM contacts WHERE id=?", (contact_id,)).fetchone()
        if not contact:
            return None
        evidence = evidence_for(self.store, contact, now_ts())
        verdict = jev.assess(evidence)
        if verdict:
            self.store.add_assessment(contact_id, call_id, verdict, evidence)
            if call_id:
                self._maybe_alert(contact, call_id, verdict, evidence)
        return verdict

    def _maybe_alert(self, contact: sqlite3.Row, call_id: str, verdict: dict[str, Any], evidence: dict[str, Any]) -> None:
        """Alert on a crossing, not a reading: once per call when the judgment reaches 'high'
        (>= 0.7), and once when it reaches 'watch' (>= 0.4 and up 0.2 on the baseline). The
        baseline is the last verdict before this call started, so a caller who already looked
        bad yesterday still gets today's alert, and a refresh at the same level stays silent."""
        p = verdict["fraud_likely"]
        baseline = self.store.conn.execute(
            "SELECT fraud_likely FROM assessments WHERE contact_id=? AND (call_id IS NULL OR call_id<>?) "
            "ORDER BY ts DESC LIMIT 1", (contact["id"], call_id)).fetchone()
        base = baseline[0] if baseline else 0.0
        level = "high" if p >= 0.7 else "watch" if p >= 0.4 and p - base >= 0.2 else None
        if not level or (call_id, level) in self._alerted:
            return
        if level == "watch" and (call_id, "high") in self._alerted:
            return
        self._alerted.add((call_id, level))
        title, body = verdict_alert(level, verdict, evidence, contact["label"])
        self.store.push_alert(title, body)


PATTERN_WORDS = {"romance": "a romance scam", "impersonation": "a bank or tech-support impersonation scam",
                 "investment": "an investment scam", "family_emergency": "a family-emergency scam", "none": "no known scam"}


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
ASSESSOR = Assessor(STORE)


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
    final: bool = False                                         # this chunk's text won't change again


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


def raise_live_alert(store: Store, call: dict[str, Any], label: str) -> None:
    who = store.conn.execute("SELECT label FROM contacts WHERE id=?", (call["contact_id"],)).fetchone()[0]
    store.push_alert(f"On this call: {LABEL_WORDS[label]}",
                     LIVE_ALERTS[label] + ("" if who == "Unknown caller" else f"\n\n(The caller: {who}.)"))


@app.post("/calls/transcript")
def call_transcript(t: TranscriptIn) -> dict[str, Any]:
    """The listener (or the demo script) sends what it hears on the current call. Only the
    labels and, if enabled, the flagged sentence are kept; the rest is dropped here."""
    heard = STORE.hear(t.chunk, t.text, t.final)
    call = STORE.current_call()
    for h in heard:
        if h["alert"] and call:
            raise_live_alert(STORE, call, h["label"])
    if heard:
        ASSESSOR.poke()
    return {"heard": [{k: h[k] for k in ("label", "confidence", "snippet", "source")} for h in heard]}


@app.post("/assess")
def assess_now() -> dict[str, Any]:
    """Jev judges every known caller against their history right now (the demo's 'Load 3-week
    story' calls this, so the cards fill in without waiting for a call)."""
    out = {}
    for c in STORE.conn.execute("SELECT id, label FROM contacts").fetchall():
        v = ASSESSOR.run(c["id"], None)
        out[c["label"]] = v and {"fraud_likely": v["fraud_likely"], "pattern": v["pattern"]}
    return {"assessed": out, "jev": jev.STATUS.snapshot()}


@app.get("/state")
def state() -> dict[str, Any]:
    return {"device": STORE.device(), "track": track(STORE), "alert": STORE.alert_after(0), "jev": jev.STATUS.snapshot()}


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
