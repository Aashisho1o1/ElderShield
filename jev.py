"""
Jev (TypeSafe AI) as the second listener on a call.

The phrase rules in server.py catch the obvious wording ("gift cards"). Jev catches the rest:
"I'm a bit short until my pension clears, could you help me out?" is a money request with no
keyword in it. Each warning sign is one yes/no question; Jev answers them all in parallel in a
few hundred milliseconds, with a calibrated probability each.

Jev sees one sentence of the call at a time and returns numbers; it never writes a word that
reaches the senior. Set OPENROUTER_API_KEY (Jev via OpenRouter's Decisions API) or
TYPESAFE_API_KEY (TypeSafe directly) to turn it on; without either, the rules run alone.

    POST https://openrouter.ai/api/alpha/decisions        (or https://api.typesafe.ai/v1/systemone)
    {"model": "typesafe/jev-1.14", "state": "<sentence>", "questions": {"<id>": {"type": "noul", "instructions": "..."}}}
    -> {"answers": {"<id>": {"type": "noul", "noul": 0.93}}, "model": "...", "usage": {...}}
"""

import json
import os
import threading
import time
import urllib.error
import urllib.request
from typing import Callable, Optional

THRESHOLD = float(os.environ.get("ELDERSHIELD_JEV_THRESHOLD", "0.6"))   # a label counts from this probability
TIMEOUT_S = 4.0

# One statement per warning sign, phrased so that a high answer means yes. Keep in step with the
# labels in server.py: the journal, alerts and scoring are keyed by these names.
QUESTIONS = {
    "endearment": "The speaker uses romantic or loving language toward the listener (calling them my love, "
                  "darling, saying I love you, or similar).",
    "future_faking": "The speaker promises a shared future with the listener: meeting, visiting, marrying, "
                     "moving in, or a life together.",
    "avoids_meeting": "The speaker gives a reason why they cannot meet in person or on video (a broken camera, "
                      "being deployed, on an oil rig, abroad with no access, a frozen account, or similar).",
    "isolation_secrecy": "The speaker asks the listener to keep something secret or not tell family or friends.",
    "money_request": "The speaker asks the listener for money, a loan, a payment, a transfer, or help paying a "
                     "fee, bill, ticket, or emergency.",
    "gift_cards": "The speaker asks the listener to buy gift cards or prepaid cards, or to read card numbers aloud.",
    "crypto_investment": "The speaker talks about cryptocurrency, a trading platform, or an investment with "
                         "promised or guaranteed returns.",
    "remote_access": "The speaker asks the listener to install an app, give remote access to their computer, "
                     "or share their screen.",
    "one_time_code": "The speaker asks the listener to read out a verification code, one-time code, or PIN "
                     "they received.",
    "threat_urgency": "The speaker pressures the listener to act immediately or threatens consequences "
                      "(arrest, a warrant, an account being frozen, a last chance).",
}


def route() -> Optional[tuple[str, str, str]]:
    """(url, model, key) for whichever key is set; OpenRouter first. Env overrides for tests."""
    if key := os.environ.get("OPENROUTER_API_KEY"):
        return (os.environ.get("JEV_API_URL", "https://openrouter.ai/api/alpha/decisions"),
                os.environ.get("JEV_MODEL", "typesafe/jev-1.14"), key)
    if key := os.environ.get("TYPESAFE_API_KEY"):
        return (os.environ.get("JEV_API_URL", "https://api.typesafe.ai/v1/systemone"),
                os.environ.get("JEV_MODEL", "jev-latest"), key)
    return None


def enabled() -> bool:
    return route() is not None


class Status:
    """What the page shows: whether Jev is on, and how its last call went."""
    def __init__(self) -> None:
        self.calls = 0
        self.errors = 0
        self.last_ms: Optional[float] = None
        self.last_error: Optional[str] = None
        self.model: Optional[str] = None

    def snapshot(self) -> dict:
        return {"enabled": enabled(), "calls": self.calls, "errors": self.errors, "last_ms": self.last_ms,
                "last_error": self.last_error, "model": self.model}


STATUS = Status()


def ask(sentence: str) -> dict[str, float]:
    """Probability per label for one sentence. Raises on any API problem."""
    url, model, key = route()
    body = {"model": model, "state": sentence,
            "questions": {k: {"type": "noul", "instructions": v} for k, v in QUESTIONS.items()}}
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST", headers={
        "Authorization": f"Bearer {key}", "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/Aashisho1o1/ElderShield", "X-Title": "ElderShield"})
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
            data = json.loads(r.read())
    except urllib.error.HTTPError as e:
        detail = e.read()[:200].decode(errors="replace")
        raise RuntimeError(f"HTTP {e.code}: {detail}") from e
    STATUS.last_ms = round((time.perf_counter() - t0) * 1000)
    STATUS.model = data.get("model")
    answers = data.get("answers", {})
    return {k: float(answers[k]["noul"]) for k in QUESTIONS if k in answers and "noul" in answers[k]}


def classify(sentence: str) -> list[tuple[str, float]]:
    """(label, probability) for every warning sign Jev hears in this sentence. Empty when off or failing."""
    if not enabled() or len(sentence.split()) < 3:
        return []
    STATUS.calls += 1
    try:
        probs = ask(sentence)
        STATUS.last_error = None
    except Exception as e:                    # network, auth, rate limit, malformed: the rules still ran
        STATUS.errors += 1
        STATUS.last_error = str(e)[:160]
        return []
    return [(label, round(p, 2)) for label, p in probs.items() if p >= THRESHOLD]


def classify_async(sentence: str, then: Callable[[list[tuple[str, float]]], None]) -> None:
    """Run classify() off the request thread and hand the labels to `then`."""
    if not enabled():
        return
    threading.Thread(target=lambda: then(classify(sentence)), daemon=True).start()
