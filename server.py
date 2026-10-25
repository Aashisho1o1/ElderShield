"""
ElderShield — a payment guardian with a memory
==============================================

A local daemon that sits between an older adult and their bank. `device_watch.py` tells it
what is happening on this Mac (a live call and who with, a remote-control app) and, if
listening is switched on, what is being asked on the call. ElderShield keeps a journal of
calls and the warning signs heard in them, tracks each caller over weeks (the slow pattern of
a romance or investment scam), and when the senior tries to send money it pauses the payment
with a plain-language alert if the moment or the history calls for it.

The journal, the payments, Jev's judgments and her circle live in SpacetimeDB (spacetimedb/):
the module's reducers are the only way to write them, and only this daemon's identity may.
The people she has chosen to tell subscribe to the module's views and see only what she shares.

Run:
    pip install -r requirements.txt
    spacetime start                  # the database (or point SPACETIME_URL at Maincloud)
    spacetime publish eldershield --server local
    python server.py                 # then open http://127.0.0.1:8777
    python device_watch.py           # second terminal
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.request
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
INDEX_PATH = HERE / "index.html"
# The journal lives in SpacetimeDB: `spacetime start` locally, or a Maincloud database.
SPACETIME_URL = os.environ.get("SPACETIME_URL", "http://127.0.0.1:3000").rstrip("/")
SPACETIME_DB = os.environ.get("SPACETIME_DB", "eldershield")
ELDER_NAME = os.environ.get("ELDERSHIELD_NAME", "Margaret")      # how her circle sees her named
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


class SpacetimeError(RuntimeError):
    def __init__(self, status: int, message: str):
        super().__init__(f"SpacetimeDB {status}: {message}")
        self.status = status


class Spacetime:
    """The daemon's line to the database: reducer calls to write, SQL to read, both over HTTP
    as the identity that published the module, the only one the module lets write the journal.
    The token is the one `spacetime publish` saved (or SPACETIME_TOKEN)."""

    def __init__(self, url: str = SPACETIME_URL, database: str = SPACETIME_DB, token: Optional[str] = None):
        self.base = f"{url}/v1/database/{database}"
        self.token = token or os.environ.get("SPACETIME_TOKEN") or self._cli_token()
        if not self.token:
            raise SystemExit("No SpacetimeDB token: run `spacetime publish eldershield --server local` once, "
                             "or set SPACETIME_TOKEN.")

    @staticmethod
    def _cli_token() -> Optional[str]:
        try:
            import tomllib
            return tomllib.loads((Path.home() / ".config/spacetime/cli.toml").read_text()).get("spacetimedb_token")
        except (OSError, ValueError):
            return None

    def _post(self, path: str, body: bytes, content_type: str) -> Any:
        req = urllib.request.Request(self.base + path, data=body, method="POST", headers={
            "Authorization": f"Bearer {self.token}", "Content-Type": content_type})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                raw = r.read()
        except urllib.error.HTTPError as e:
            raise SpacetimeError(e.code, e.read()[:300].decode(errors="replace")) from None
        except urllib.error.URLError as e:
            raise SpacetimeError(0, f"can't reach SpacetimeDB at {self.base}: {e.reason}") from None
        return json.loads(raw) if raw else None

    def call(self, reducer: str, *args: Any) -> None:
        """Run a reducer. Raises SpacetimeError(530, reason) when the module refuses."""
        self._post(f"/call/{reducer}", json.dumps(list(args)).encode(), "application/json")

    def sql(self, query: str) -> list[dict[str, Any]]:
        """One SELECT, as a list of dicts. SpacetimeDB's SQL has no ORDER BY; callers sort."""
        result = self._post("/sql", query.encode(), "text/plain")[0]
        cols = [(e["name"]["some"], e["algebraic_type"]) for e in result["schema"]["elements"]]
        return [{name: _decode(ty, v) for (name, ty), v in zip(cols, row)} for row in result["rows"]]


def _decode(ty: dict[str, Any], v: Any) -> Any:
    """SATS-JSON to Python: an Option comes as [0, value] / [1, []]."""
    if "Sum" in ty:
        names = [x["name"]["some"] for x in ty["Sum"]["variants"]]
        if names == ["some", "none"]:
            return v[1] if v[0] == 0 else None
    return v


def lit(v: Any) -> str:
    """A SQL literal for our own values: ids, labels, timestamps."""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return repr(float(v))
    return "'" + str(v).replace("'", "''") + "'"


class Store(Spacetime):
    """Everything ElderShield remembers, kept in SpacetimeDB; plus what is true right now
    (the sensor's last report, the private alerts), which lives only in memory."""

    def __init__(self) -> None:
        super().__init__()
        self._lock = Lock()
        self.report: dict[str, Any] = {}
        self.reported_at = 0.0
        self.alerts: list[dict[str, Any]] = []     # recent private alerts, newest first; the sensor shows each
        self._heard: set[str] = set()                   # signal keys already written this run
        self._alerted: set[tuple[str, str]] = set()     # (call, label) already alerted
        self._asked_jev: set[tuple[str, str]] = set()   # (call, sentence) Jev has already been asked about
        self._family_seen: set[int] = set()             # family alerts whose acknowledgement she has been told of
        self.call("ensure_household", ELDER_NAME, now_ts())

    # -- device and calls ----------------------------------------------------
    def update_device(self, report: dict[str, Any]) -> None:
        now = now_ts()
        with self._lock:
            self.report, self.reported_at = report, now
            for name in report["remote_access"]:
                self.call("note_remote_access", name, now)
            self._sync_call(report, now)

    def _sync_call(self, report: dict[str, Any], at: float) -> None:
        """Open a journal entry when a call starts, close it when it ends (lock held)."""
        open_call = self.current_call()
        if report.get("call_app") and not open_call:
            contact = self._contact(report.get("caller"), at)
            self.call("start_call", "call_" + uuid.uuid4().hex[:10], contact, report["call_app"], at,
                      json.dumps(report["remote_access"]))
        elif open_call and not report.get("call_app"):
            self.call("end_call", open_call["id"], at)
        elif open_call and report["remote_access"]:
            seen = sorted(set(json.loads(open_call["remote_access"])) | set(report["remote_access"]))
            if seen != json.loads(open_call["remote_access"]):
                self.call("set_call_remote_access", open_call["id"], json.dumps(seen))

    def _contact(self, caller: Optional[str], at: float) -> str:
        cid = salted_hash(caller) if caller else "unknown"
        self.call("upsert_contact", cid, caller or "Unknown caller", at)
        return cid

    def device(self) -> dict[str, Any]:
        """Reports expire, so a sensor that stops reporting never leaves a stale 'call live' behind."""
        now = now_ts()
        with self._lock:
            live = self.report if now - self.reported_at < DEVICE_REPORT_TTL_S else {}
            if not live and self.reported_at:                 # sensor went quiet: end any open call
                self._sync_call({"call_app": None, "remote_access": []}, self.reported_at)
            seen = sorted(r["name"] for r in self.sql(
                f"SELECT name FROM remote_access_seen WHERE last_seen >= {lit(now - REMOTE_ACCESS_MEMORY_S)}"))
        running = live.get("remote_access", [])
        return {
            "sensor_live": bool(live),
            "call_app": live.get("call_app"),
            "caller": live.get("caller") if live.get("call_app") else None,
            "remote_access": running,
            "remote_access_earlier": [n for n in seen if n not in running],
            "private_window": bool(live.get("private_window")),
        }

    # -- reads the track and the scoring need (SpacetimeDB SQL has no ORDER BY: sorted here) --
    @staticmethod
    def _call_row(r: dict[str, Any]) -> dict[str, Any]:
        return {**r, "ended": None if r["live"] else r["ended"]}

    def current_call(self) -> Optional[dict[str, Any]]:
        rows = self.sql("SELECT * FROM call_log WHERE live = true")
        return self._call_row(rows[0]) if rows else None

    def contacts(self) -> list[dict[str, Any]]:
        return self.sql("SELECT * FROM contact")

    def contact_label(self, contact_id: str) -> str:
        rows = self.sql(f"SELECT label FROM contact WHERE id = {lit(contact_id)}")
        return rows[0]["label"] if rows else "Unknown caller"

    def calls_for(self, contact_id: str, since: float) -> list[dict[str, Any]]:
        rows = self.sql(f"SELECT * FROM call_log WHERE contact_id = {lit(contact_id)} AND started >= {lit(since)}")
        return sorted((self._call_row(r) for r in rows), key=lambda c: c["started"])

    def recent_calls(self, n: int) -> list[dict[str, Any]]:
        rows = sorted(self.sql("SELECT * FROM call_log"), key=lambda c: -c["started"])
        return [self._call_row(r) for r in rows[:n]]

    def count_calls(self, start: float, end: float) -> int:
        return self.sql(f"SELECT COUNT(*) AS n FROM call_log WHERE started >= {lit(start)} AND started < {lit(end)}")[0]["n"]

    @staticmethod
    def _signal_row(r: dict[str, Any]) -> dict[str, Any]:
        return {**r, "snippet": r["snippet"] or None}

    def signals_for(self, contact_id: str, since: float) -> list[dict[str, Any]]:
        rows = self.sql(f"SELECT * FROM signal WHERE contact_id = {lit(contact_id)} AND ts >= {lit(since)}")
        return sorted((self._signal_row(r) for r in rows), key=lambda s: s["ts"])

    def signals_for_call(self, call_id: str) -> list[dict[str, Any]]:
        rows = self.sql(f"SELECT * FROM signal WHERE call_id = {lit(call_id)}")
        return sorted((self._signal_row(r) for r in rows), key=lambda s: s["ts"])

    def latest_ask(self, since: float) -> Optional[dict[str, Any]]:
        """The most recent money/gift-card/crypto ask heard on any call since `since`, with who said it."""
        rows = [s for s in self.sql(f"SELECT * FROM signal WHERE ts >= {lit(since)}") if s["label"] in ASK_LABELS]
        if not rows:
            return None
        ask = max(rows, key=lambda s: s["ts"])
        return {**ask, "who": self.contact_label(ask["contact_id"])}

    @staticmethod
    def _payment_row(r: dict[str, Any]) -> dict[str, Any]:
        return {**r, "amount": None if r["amount"] < 0 else r["amount"],
                "call_id": r["call_id"] or None, "released_by": r["released_by"] or None}

    def payments_for_call(self, call_id: str) -> list[dict[str, Any]]:
        return [self._payment_row(r) for r in self.sql(f"SELECT * FROM payment WHERE call_id = {lit(call_id)}")]

    def payments_since(self, ts: float, decision: Optional[str] = None) -> list[dict[str, Any]]:
        where = f"ts >= {lit(ts)}" + (f" AND decision = {lit(decision)}" if decision else "")
        return [self._payment_row(r) for r in self.sql(f"SELECT * FROM payment WHERE {where}")]

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
                key = f"{call['id']}:{chunk}:{label}:{source}"
                snippet = snippet_around(text, pos) if KEEP_SNIPPETS else ""
                if key in self._heard:          # the same chunk again, usually more of the sentence
                    if source == "rules":
                        self.call("add_signal", key, call["id"], call["contact_id"], now_ts(), label, conf, snippet, source)
                    continue
                self.call("add_signal", key, call["id"], call["contact_id"], now_ts(), label, conf, snippet, source)
                self._heard.add(key)
                new.append({"label": label, "confidence": conf, "snippet": snippet or None, "source": source,
                            "alert": (call["id"], label) not in self._alerted and label in LIVE_ALERTS})
                self._alerted.add((call["id"], label))
        return new

    # -- private alerts, and the circle she has chosen to tell ---------------
    def push_alert(self, title: str, body: str, family: Optional[tuple[str, str, str]] = None) -> None:
        """An alert for her private window (none if the title is empty). `family` = (kind, title,
        body) also tells the people in her circle, in fewer words; the module shows it only to
        those she has let in, and only the kinds she has chosen to share."""
        if title:
            with self._lock:
                self.alerts.insert(0, {"ts": now_ts(), "title": title, "body": body})
                del self.alerts[10:]
        if family:
            kind, ftitle, fbody = family
            try:
                self.call("post_family_alert", kind, ftitle, fbody, now_ts())
            except SpacetimeError as e:
                print(f"family alert not posted: {e}")

    def alert_after(self, after: float) -> list[dict[str, Any]]:
        """Alerts newer than the sensor's cursor, newest first. Timestamps, not ids, so a daemon
        restart can't strand the cursor; and only recent ones, so a sensor that starts late
        doesn't pop up yesterday's warning. A list, so two warning signs a second apart (the
        rule's alert, then Jev's) both reach her."""
        cutoff = max(after, now_ts() - 30)
        with self._lock:
            return [a for a in self.alerts if a["ts"] > cutoff]

    def notice_family(self) -> list[dict[str, Any]]:
        """Recent alerts to her circle, newest first. The first time someone has answered one,
        she gets a private line saying who is on the way. The assessor calls this every couple of
        seconds, so the line reaches her window whether or not her page is open."""
        alerts = sorted(self.sql("SELECT * FROM family_alert"), key=lambda a: -a["ts"])[:8]
        for a in alerts:
            if a["acknowledged_by"] and a["id"] not in self._family_seen:
                self._family_seen.add(a["id"])
                if now_ts() - a["acknowledged_at"] < 120:
                    self.push_alert(f"{a['acknowledged_by']} has seen this and is calling you",
                                    "You don't have to decide anything until you've talked to them.")
        return alerts

    def elder_name(self) -> str:
        """How her circle knows her: what she set on her page, else the configured default."""
        h = self.sql("SELECT elder_name FROM household")
        return h[0]["elder_name"] if h else ELDER_NAME

    def family(self) -> dict[str, Any]:
        """Her circle as the page shows it."""
        h = self.sql("SELECT * FROM household")
        people = sorted(self.sql("SELECT * FROM trusted_person"), key=lambda p: p["added_at"])
        alerts = self.notice_family()
        return {
            "elder_name": h[0]["elder_name"] if h else ELDER_NAME,
            "share_level": h[0]["share_level"] if h else "payments",
            "people": [{"id": p["id"], "name": p["name"], "relation": p["relation"], "code": p["invite_code"],
                        "joined": p["identity"] is not None} for p in people],
            "alerts": [{"id": a["id"], "ts": iso(a["ts"]), "kind": a["kind"], "title": a["title"],
                        "acknowledged_by": a["acknowledged_by"] or None} for a in alerts],
        }

    # -- payments and releases -----------------------------------------------
    def record_payment(self, action_id: str, fingerprint: str, action_type: str, amount: Optional[float],
                       decision: str, score: int, released_by: Optional[str] = None) -> None:
        call = self.current_call()
        self.call("record_payment", action_id, now_ts(), fingerprint, action_type,
                  -1.0 if amount is None else float(amount), decision, int(score),
                  call["id"] if call else "", released_by or "")

    def payment(self, action_id: str) -> Optional[dict[str, Any]]:
        rows = self.sql(f"SELECT * FROM payment WHERE action_id = {lit(action_id)}")
        return self._payment_row(rows[0]) if rows else None

    def add_override(self, token: str, action_id: str, fingerprint: str, decision: str) -> float:
        now = now_ts()
        self.call("add_release", token, action_id, fingerprint, decision, now, now + OVERRIDE_WINDOW_S)
        return now + OVERRIDE_WINDOW_S

    def take_override(self, token: str, fingerprint: str) -> Optional[dict[str, Any]]:
        """Single use, bound to one exact payment, and only within its window: the module checks
        and marks it in one transaction, so two clicks can't both get through."""
        try:
            self.call("take_release", token, fingerprint, now_ts())
        except SpacetimeError as e:
            if e.status == 530:
                return None
            raise
        rows = self.sql(f"SELECT * FROM release WHERE token = {lit(token)}")
        return rows[0] if rows else None

    def add_assessment(self, contact_id: str, call_id: Optional[str], verdict: dict[str, Any], evidence: dict[str, Any]) -> None:
        self.call("add_assessment", now_ts(), contact_id, call_id or "", verdict["fraud_likely"],
                  verdict["financial_steering"], verdict["isolation"], verdict["escalation"], verdict["pattern"],
                  verdict["pattern_confidence"], json.dumps(evidence), verdict.get("model") or "", int(verdict.get("ms") or 0))

    def assessments_for(self, contact_id: str) -> list[dict[str, Any]]:
        """Newest first."""
        rows = self.sql(f"SELECT * FROM assessment WHERE contact_id = {lit(contact_id)}")
        return sorted(rows, key=lambda a: -a["ts"])

    def latest_assessment(self, contact_id: str) -> Optional[dict[str, Any]]:
        rows = self.assessments_for(contact_id)
        if not rows:
            return None
        d = dict(rows[0])
        d["call_id"] = d["call_id"] or None
        d["evidence"] = json.loads(d["evidence"])
        d["previous_fraud_likely"] = rows[1]["fraud_likely"] if len(rows) > 1 else None
        d["ago"] = ago(now_ts() - d["ts"])
        return d

    def clear(self) -> None:
        with self._lock:
            self.call("clear_journal")
            self.alerts.clear()
            self._heard.clear()
            self._alerted.clear()
            self._asked_jev.clear()
            self._family_seen.clear()


# --------------------------------------------------------------------------- #
# The track: what the journal says about each caller, and about her week
# --------------------------------------------------------------------------- #

STAGES = ["", "no warning signs", "love-bombing", "isolating you", "asking for money", "escalating"]


def _minutes(call: dict[str, Any], now: float) -> float:
    return ((call["ended"] or now) - call["started"]) / 60


def _late(ts: float) -> bool:
    h = datetime.fromtimestamp(ts).hour
    return h >= 22 or h < 6


def contact_track(store: Store, contact: dict[str, Any], now: float) -> dict[str, Any]:
    since = now - HISTORY_DAYS * DAY
    calls = store.calls_for(contact["id"], since)
    sigs = store.signals_for(contact["id"], since)
    days_known = max(0, int((now - contact["first_seen"]) // DAY))
    week = [c for c in calls if c["started"] >= now - 7 * DAY]
    prev = [c for c in calls if now - 14 * DAY <= c["started"] < now - 7 * DAY]
    avg = lambda cs: round(sum(_minutes(c, now) for c in cs) / len(cs)) if cs else 0
    labels = {s["label"] for s in sigs}
    ask_days = {int(s["ts"] // DAY) for s in sigs if s["label"] in ASK_LABELS}
    first_ask = min((s["ts"] for s in sigs if s["label"] in ASK_LABELS), default=None)
    paid_after_ask = first_ask is not None and bool(store.payments_since(first_ask))
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
    contacts = [contact_track(store, c, now) for c in store.contacts()]
    contacts = [c for c in contacts if c["calls"]]
    contacts.sort(key=lambda c: (-c["stage"], -c["calls_this_week"]))
    names = {c["id"]: c["name"] for c in contacts}

    recent = []
    for call in store.recent_calls(12):
        sigs = store.signals_for_call(call["id"])
        paid = store.payments_for_call(call["id"])
        recent.append({
            "id": call["id"], "who": names.get(call["contact_id"], "Unknown caller"), "app": call["app"],
            "started": iso(call["started"]), "live": call["ended"] is None, "minutes": round(_minutes(call, now)),
            "late": _late(call["started"]), "remote_access": json.loads(call["remote_access"]),
            "heard": [{"label": s["label"], "words": LABEL_WORDS[s["label"]], "snippet": s["snippet"],
                       "source": s["source"], "confidence": s["confidence"]} for s in sigs],
            "payments": [{"amount": p["amount"], "decision": p["decision"]} for p in paid],
        })

    # Her own week against her usual, so a change in behaviour shows even before anyone asks.
    weeks = [store.count_calls(now - (w + 1) * 7 * DAY, now - w * 7 * DAY) for w in range(5)]
    usual = sum(weeks[1:]) / 4
    you = {"calls_this_week": weeks[0], "usual_calls_per_week": round(usual, 1),
           "change": (f"{weeks[0]} calls this week; usually about {round(usual)}" if usual and weeks[0] >= 2 * usual
                      else None)}
    return {"contacts": contacts, "recent_calls": recent, "you": you}


def memory_for_payment(store: Store) -> tuple[dict[str, int], list[str]]:
    """What the journal adds to a payment: a recent ask on a call, and any caller's long pattern."""
    now = now_ts()
    comp, reasons = {}, []
    ask = store.latest_ask(now - RECENT_ASK_S)
    if ask:
        comp["money_asked_on_call"] = WEIGHTS["money_asked_on_call"]
        who = "someone" if ask["who"] == "Unknown caller" else ask["who"]
        reasons.append(f"{who} {LABEL_WORDS[ask['label']]} on a call {ago(now - ask['ts'])}")
    top = max((contact_track(store, c, now) for c in store.contacts()), key=lambda t: t["stage"], default=None)
    ladder = 0
    if top and top["stage"] >= 3:
        key = {3: "pattern_isolating", 4: "pattern_asking", 5: "pattern_escalating"}[top["stage"]]
        ladder = WEIGHTS[key]
        reasons.append(f"{top['name']}, someone you've known for {top['days_known']} days, has been "
                       + {3: "isolating you", 4: "asking you for money", 5: "asking for more and more money"}[top["stage"]])
    # Jev's judgment of the same history (layer 2): it sees the combination the ladder can't.
    # The ladder stays as the floor, so a Jev outage or a low reading never weakens the rules.
    judged = max((a for a in (store.latest_assessment(c["id"]) for c in store.contacts())
                  if a and now - a["ts"] < HISTORY_DAYS * DAY), key=lambda a: a["fraud_likely"], default=None)
    jev_points = int(round(WEIGHTS["pattern_escalating"] * judged["fraud_likely"])) if judged and judged["fraud_likely"] >= 0.5 else 0
    if jev_points:
        comp["long_term_pattern"] = max(ladder, jev_points)   # the ladder is the floor
        who = store.contact_label(judged["contact_id"])
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


def evidence_for(store: Store, contact: dict[str, Any], now: float) -> dict[str, Any]:
    """What Jev sees: counts, labels and amounts from the journal. Never the words."""
    since = now - HISTORY_DAYS * DAY
    calls = store.calls_for(contact["id"], since)
    week = [c for c in calls if c["started"] >= now - 7 * DAY]
    before = [c for c in calls if c["started"] < now - 7 * DAY]
    avg = lambda cs: round(sum(_minutes(c, now) for c in cs) / len(cs)) if cs else 0
    sigs = store.signals_for(contact["id"], since)
    amounts = []
    for sg in sigs:
        if sg["label"] in ASK_LABELS and sg["snippet"]:
            for m in re.findall(r"\$\s?(\d[\d,]*)|(\d[\d,]*)\s*(?:dollars|bucks)", sg["snippet"]):
                amounts.append(int((m[0] or m[1]).replace(",", "")))
    first_ask = min((sg["ts"] for sg in sigs if sg["label"] in ASK_LABELS), default=None)
    paid = [p["amount"] for p in store.payments_since(first_ask, "ALLOW")] if first_ask else []
    live = store.current_call()
    by_call: dict[str, list[str]] = {}
    for sg in sigs:
        by_call.setdefault(sg["call_id"], []).append(sg["label"])
    earlier = [{"days_ago": round((now - c["started"]) / DAY, 1), "minutes": round(_minutes(c, now)),
                "late_night": _late(c["started"]), "heard": by_call.get(c["id"], [])}
               for c in calls if not live or c["id"] != live["id"]][-12:]
    usual = store.count_calls(now - 35 * DAY, now - 7 * DAY) / 4
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
                self.store.notice_family()                  # "Sarah is calling you", page open or not
                live = self.store.current_call()
                if live:
                    self._last_call = live["id"]
                    self.run(live["contact_id"], live["id"])
                elif self._last_call:                       # the call just ended: one final judgment
                    ended = self.store.sql(f"SELECT contact_id FROM call_log WHERE id = {lit(self._last_call)}")
                    self._last_call = None
                    if ended:
                        self.run(ended[0]["contact_id"], None)
            except Exception as e:                          # never let the loop die
                jev.STATUS.last_error = f"assessor: {e}"[:160]

    def run(self, contact_id: str, call_id: Optional[str]) -> Optional[dict[str, Any]]:
        if not jev.enabled():
            return None
        found = self.store.sql(f"SELECT * FROM contact WHERE id = {lit(contact_id)}")
        if not found:
            return None
        contact = found[0]
        evidence = evidence_for(self.store, contact, now_ts())
        verdict = jev.assess(evidence)
        if verdict:
            self.store.add_assessment(contact_id, call_id, verdict, evidence)
            if call_id:
                self._maybe_alert(contact, call_id, verdict, evidence)
        return verdict

    def _maybe_alert(self, contact: dict[str, Any], call_id: str, verdict: dict[str, Any], evidence: dict[str, Any]) -> None:
        """Alert on a crossing, not a reading: once per call when the judgment reaches 'high'
        (>= 0.7), and once when it reaches 'watch' (>= 0.4 and up 0.2 on the baseline). The
        baseline is the last verdict before this call started, so a caller who already looked
        bad yesterday still gets today's alert, and a refresh at the same level stays silent."""
        p = verdict["fraud_likely"]
        baseline = next((a for a in self.store.assessments_for(contact["id"]) if a["call_id"] != call_id), None)
        base = baseline["fraud_likely"] if baseline else 0.0
        level = "high" if p >= 0.7 else "watch" if p >= 0.4 and p - base >= 0.2 else None
        if not level or (call_id, level) in self._alerted:
            return
        if level == "watch" and (call_id, "high") in self._alerted:
            return
        self._alerted.add((call_id, level))
        title, body = verdict_alert(level, verdict, evidence, contact["label"])
        family = None
        if level == "high":
            who = "someone" if contact["label"] == "Unknown caller" else contact["label"]
            family = ("warning", f"A call with {who} looks like {PATTERN_WORDS.get(verdict['pattern'], 'a scam')}",
                      f"{self.store.elder_name()} is on a call right now. Jev judges the pattern of calls with {who} "
                      f"{int(verdict['fraud_likely'] * 100)}% likely fraud. ElderShield has warned her; "
                      "nothing has been sent. A call from you would help.")
        self.store.push_alert(title, body, family)


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

    if paused:
        amount = f" ${a.amount:,.0f}" if a.amount else " this payment"
        # Her circle hears about a paused payment (if she has let anyone in): what was paused and
        # the first reason, in a sentence; never the account details.
        family = ("payment", f"ElderShield paused a{amount} {a.action_type.replace('_', ' ')}",
                  f"{STORE.elder_name()} was about to send{amount}" + (f" while {s['reasons'][0]}" if s["reasons"] else "")
                  + ". ElderShield paused it and told her privately. Nothing has been sent. A call from you would help.")
        if private_overlay:
            STORE.push_alert(f"Wait — before you send{amount}",
                             "\n".join(f"• {r[0].upper()}{r[1:]}" for r in s["reasons"])
                             + "\n\nIt's safe to hang up. The other person only sees a “processing” screen. "
                             + "When you've hung up, press the button on the bank page.", family)
        else:
            STORE.push_alert("", "", family)
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
    who = store.contact_label(call["contact_id"])
    store.push_alert(f"On this call: {LABEL_WORDS[label]}",
                     LIVE_ALERTS[label] + ("" if who == "Unknown caller" else f"\n\n(The caller: {who}.)"),
                     family=("warning", f"On a call, {'someone' if who == 'Unknown caller' else who} {LABEL_WORDS[label]}",
                             f"{store.elder_name()} is on a {call['app']} call right now. ElderShield heard that the caller "
                             f"{LABEL_WORDS[label]} and has warned her privately. Nothing has been sent."))


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
    for c in STORE.contacts():
        v = ASSESSOR.run(c["id"], None)
        out[c["label"]] = v and {"fraud_likely": v["fraud_likely"], "pattern": v["pattern"]}
    return {"assessed": out, "jev": jev.STATUS.snapshot()}


@app.get("/state")
def state() -> dict[str, Any]:
    family = STORE.family()          # first: it may add the private line the alert list below carries
    return {"device": STORE.device(), "track": track(STORE), "alert": STORE.alert_after(0),
            "jev": jev.STATUS.snapshot(), "family": family}


# --- her circle: who she tells, and how much. Hers to change, from her own page only. ---------

class PersonIn(BaseModel):
    name: str = Field(min_length=1, max_length=60)
    relation: str = Field("", max_length=40)


class PersonId(BaseModel):
    id: int


class ShareIn(BaseModel):
    level: str = Field(pattern="^(payments|warnings)$")


class NameIn(BaseModel):
    name: str = Field(min_length=1, max_length=60)


@app.post("/family/people")
def add_person(p: PersonIn) -> dict[str, Any]:
    """She adds someone; the code that comes back is what she gives them. Nobody can add themselves."""
    STORE.call("add_trusted_person", p.name.strip(), p.relation.strip(), now_ts())
    return STORE.family()


@app.post("/family/people/remove")
def remove_person(p: PersonId) -> dict[str, Any]:
    """Removing someone also takes every alert out of their view, at once."""
    STORE.call("remove_trusted_person", p.id)
    return STORE.family()


@app.post("/family/share")
def set_share(s: ShareIn) -> dict[str, Any]:
    STORE.call("set_share_level", s.level)
    return STORE.family()


@app.post("/family/name")
def set_name(n: NameIn) -> dict[str, Any]:
    STORE.call("set_elder_name", n.name.strip())
    return STORE.family()


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
    demo_history.seed(STORE, salted_hash, now_ts())
    return {"ok": True}


if __name__ == "__main__":
    import uvicorn

    print(f"ElderShield → http://127.0.0.1:{PORT}")
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning")
