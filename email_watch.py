"""
Feeds a real inbox into ElderShield: polls IMAP for new mail and sends each message to the
local daemon's /ingest/trigger, exactly like the simulator's "Receive this message" button.

    ELDERSHIELD_IMAP_USER=grandma@gmail.com ELDERSHIELD_IMAP_PASSWORD=<app password> python email_watch.py

Works with providers that offer IMAP with an app password (Gmail, iCloud, Yahoo, Fastmail).
Read-only: the inbox is opened read-only and fetched with BODY.PEEK, so nothing is marked read.
Only mail that arrives after start-up is ingested; older mail would land in the 30-minute hot
window as if it had just arrived.
"""

import email
import imaplib
import json
import os
import re
import time
import urllib.request
from email.policy import default as default_policy
from email.utils import parseaddr

DAEMON = "http://127.0.0.1:8777/ingest/trigger"
HOST = os.environ.get("ELDERSHIELD_IMAP_HOST", "imap.gmail.com")
USER = os.environ.get("ELDERSHIELD_IMAP_USER", "")
PASSWORD = os.environ.get("ELDERSHIELD_IMAP_PASSWORD", "")
POLL_S = int(os.environ.get("ELDERSHIELD_IMAP_POLL_S", "20"))
MAX_CHARS = 20000


def to_trigger(raw: bytes) -> dict:
    """One raw RFC 822 message -> the daemon's /ingest/trigger body."""
    msg = email.message_from_bytes(raw, policy=default_policy)
    part = msg.get_body(preferencelist=("html", "plain"))
    payload = (part.get_payload(decode=True) or b"") if part else b""
    try:
        body = payload.decode(part.get_content_charset() or "utf-8", "replace")
    except LookupError:                           # unknown charset label
        body = payload.decode("utf-8", "replace")
    # HTML is kept so the daemon's hidden-text stripper sees inline styles; blocks that never
    # render are dropped so CSS and scripts don't read as message text.
    body = re.sub(r"(?is)<(style|script|head)\b.*?</\1>", " ", body)
    # A link's real destination often hides behind friendly anchor text.
    links = sorted(set(re.findall(r"""href\s*=\s*["']https?://([^/"'?#:]+)""", body, re.I)))
    content = f"Subject: {msg.get('Subject', '')}\n{body}"[:MAX_CHARS]
    if links:
        content += "\nLinks: " + " ".join(links)
    return {"tab_id": "email", "sender": parseaddr(msg.get("From", ""))[1] or "unknown-sender",
            "content": content, "channel": "email", "has_voice_session": False}


def post(trigger: dict) -> dict:
    req = urllib.request.Request(DAEMON, data=json.dumps(trigger).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


def connect() -> imaplib.IMAP4:
    imap = imaplib.IMAP4_SSL(HOST)
    imap.login(USER, PASSWORD)
    imap.select("INBOX", readonly=True)
    return imap


def newest_uid(imap: imaplib.IMAP4) -> int:
    _, data = imap.status("INBOX", "(UIDNEXT)")
    return int(re.search(rb"UIDNEXT (\d+)", data[0]).group(1)) - 1


def poll(imap: imaplib.IMAP4, last: int) -> int:
    """Ingest every message newer than `last`; returns the new high-water mark."""
    imap.noop()                                   # lets a read-only session see new arrivals
    _, data = imap.uid("search", None, f"UID {last + 1}:*")
    for uid in sorted(int(u) for u in data[0].split()):
        if uid <= last:                           # "n:*" always matches the newest message
            continue
        _, fetched = imap.uid("fetch", str(uid), "(BODY.PEEK[])")
        res = post(to_trigger(fetched[0][1]))
        last = uid                                # only after the daemon has it
        print(f"ingested: severity {res['severity']}, signals {sorted(res['signals'])}, case {res['case_id']}")
    return last


def main() -> None:
    if not (USER and PASSWORD):
        raise SystemExit("Set ELDERSHIELD_IMAP_USER and ELDERSHIELD_IMAP_PASSWORD (an app password).")
    last = None
    while True:
        try:
            imap = connect()
            if last is None:
                last = newest_uid(imap)
                print(f"Watching {USER} on {HOST}; new mail goes to ElderShield every {POLL_S}s.")
            while True:
                last = poll(imap, last)
                time.sleep(POLL_S)
        except (imaplib.IMAP4.abort, OSError) as e:   # dropped connection or daemon down: retry
            print(f"connection problem ({e}); retrying in 10s")
            time.sleep(10)


if __name__ == "__main__":
    main()
