"""
Three weeks of call history for the demo, written straight into the journal.

"Daniel" is a romance scammer: a wrong-number opener, loving words within days, longer and
later calls, excuses not to video, "don't tell your daughter", crypto talk, then money asks
that grow ($1,200 for customs, then $8,500 for a hospital). Sarah, the daughter, calls weekly
and says nothing alarming. One unknown caller rang once.
"""

import json
from datetime import datetime, timedelta

# (days ago, hour, minutes long, app, [(label, confidence, snippet)])
DANIEL = [
    (21, 15, 6, "WhatsApp", [("endearment", 0.8, "Sorry, wrong number, but you sound lovely, my dear.")]),
    (19, 16, 14, "WhatsApp", [("endearment", 0.8, "You're such a sweetheart, I can't stop smiling.")]),
    (17, 19, 22, "WhatsApp", [("endearment", 0.8, "I think I'm falling for you, my love.")]),
    (15, 23, 31, "FaceTime", [("future_faking", 0.8, "When we meet I want to take you to Paris.")]),
    (13, 20, 28, "WhatsApp", [("avoids_meeting", 0.8, "My camera is broken out here on the oil rig, I can't video.")]),
    (11, 22, 40, "WhatsApp", [("isolation_secrecy", 0.9, "Don't tell your daughter about us, she wouldn't understand.")]),
    (9, 23, 35, "FaceTime", [("crypto_investment", 0.85, "My uncle's trading platform doubles your money in a month.")]),
    (7, 21, 45, "WhatsApp", [("future_faking", 0.8, "I'll fly to you next month, my angel."),
                             ("endearment", 0.8, "I love you more than anything.")]),
    (5, 22, 38, "WhatsApp", [("money_request", 0.7, "Customs is holding my package, I need $1,200 to pay the fee.")]),
    (3, 23, 50, "FaceTime", [("avoids_meeting", 0.8, "My bank account is frozen here, I can't get to my own money.")]),
    (2, 22, 42, "WhatsApp", [("money_request", 0.7, "The hospital needs money before they'll treat me."),
                             ("isolation_secrecy", 0.9, "Please don't tell anyone, they'll only worry.")]),
    (1, 23, 20, "FaceTime", [("endearment", 0.8, "Goodnight my love, I'll call you tomorrow.")]),
]
SARAH = [(20, 18, 12), (13, 18, 15), (6, 18, 11)]


def seed(conn, salted_hash, now: float) -> None:
    today = datetime.fromtimestamp(now).replace(hour=0, minute=0, second=0, microsecond=0)
    at = lambda days, hour: (today - timedelta(days=days) + timedelta(hours=hour)).timestamp()

    def contact(name, first_seen):
        cid = salted_hash(name)
        conn.execute("INSERT OR IGNORE INTO contacts VALUES (?,?,?)", (cid, name, first_seen))
        return cid

    def call(cid, days, hour, minutes, app, heard=()):
        start = at(days, hour)
        call_id = f"call_seed_{cid[:6]}_{days}"
        conn.execute("INSERT INTO calls VALUES (?,?,?,?,?,?)",
                     (call_id, cid, app, start, start + minutes * 60, json.dumps([])))
        for i, (label, conf, snippet) in enumerate(heard):
            conn.execute("INSERT INTO signals (call_id, contact_id, ts, label, confidence, snippet) VALUES (?,?,?,?,?,?)",
                         (call_id, cid, start + (i + 1) * 120, label, conf, snippet))
        return call_id

    daniel = contact("Daniel", at(21, 15))
    for days, hour, minutes, app, heard in DANIEL:
        call(daniel, days, hour, minutes, app, heard)
        if days == 5:   # she sent the first $1,200 the next morning
            conn.execute("INSERT INTO payments VALUES (?,?,?,?,?,?,?,?,?)",
                         ("act_seed_customs", at(4, 10), "seed", "wire_transfer", 1200, "ALLOW", 0, None, None))
    sarah = contact("Sarah (daughter)", at(60, 18))
    for days, hour, minutes in SARAH:
        call(sarah, days, hour, minutes, "FaceTime")
    unknown = "unknown"
    conn.execute("INSERT OR IGNORE INTO contacts VALUES (?,?,?)", (unknown, "Unknown caller", at(10, 11)))
    call(unknown, 10, 11, 2, "FaceTime")
    conn.commit()
