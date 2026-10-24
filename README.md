# ElderShield — a payment guardian with a memory

Romance and investment scams on older adults aren't one message; they're weeks of calls. A
stranger becomes a "friend", then a sweetheart, asks her to keep it from the family, then asks
for money, then more. Every scam filter judges one thing at a time. ElderShield remembers.

It runs on her Mac and does three things:

1. **Watches the moment.** It knows when she's on a FaceTime, Zoom, WhatsApp or phone call (and
   with whom, when the Mac's call history allows), and whether a remote-control app such as
   AnyDesk is running.
2. **Keeps a journal** of her calls in a local SQLite database: who, when, how long, and (if
   listening is on) the warning signs heard, such as loving words from a new contact, excuses not
   to video, "don't tell your daughter", requests for money, gift cards, crypto or a code. Only the
   flagged sentence is kept, with long numbers removed; never the call.
3. **Steps in when money moves.** Each caller is tracked over weeks against the romance-scam
   ladder (getting to know you → love-bombing → isolating you → asking for money → escalating).
   When she sends a payment, ElderShield combines the moment and the history and, if they add up,
   pauses it with a Cluely-style alert in plain words: *"Wait — before you send $8,500.
   Daniel, someone you've known for 20 days, has been asking for more and more money."*
   While someone may be watching her screen, the alert appears in a window screen sharing can't
   see, and the shared screen shows only a "Verifying…" stall.

Everything is stored and decided on this computer. The decision is fixed code, so nothing a
scammer says can talk it into anything.

## Run (macOS)

```bash
pip install -r requirements.txt
python server.py                    # then open http://127.0.0.1:8777
python device_watch.py              # second terminal: calls and remote control
python device_watch.py --listen     # …and listen to calls for warning signs (opt-in)
```

`device_watch.py` without `--listen` needs no macOS permissions: it reads the process list and
whether the microphone is in use. With `--listen`, macOS asks once for System Audio Recording and
Speech Recognition; the listener hears the call on this Mac and transcribes it on-device.

Check that the listener can hear a call on your Mac (start a FaceTime call first):

```bash
macos/capture-test.sh --seconds 20
```

## The demo

1. Click **Load 3-week story** on the page. Daniel's card fills in: 13 calls in 20 days, later and
   longer, every rung of the ladder, and the flagged sentences in the journal.
2. Start his "call" (no real call needed):
   ```bash
   python device_watch.py --pretend facetime --caller Daniel --script demo/romance_call.txt
   ```
   The pill shows **FaceTime call · Daniel**; every six seconds a line of the call is "heard", and
   alerts pop up only she can see ("They just asked you for money…").
3. Send the $8,500 wire. It scores 100: the live call, the ask a minute ago, and the three-week
   pattern. Her screen shows the stall; the truth is in the private window.
4. Stop the script (Ctrl-C), click **I've hung up — show me**, and the alert offers **Don't send**,
   with **Send anyway** now available.

For a real call instead: FaceTime the Mac (see below) with `--listen`, and have the caller say the
lines. Rehearse the screen-sharing part on the demo Mac: start a QuickTime screen recording while an
alert is up; the recording should show the stall but not the alert.

FaceTiming your own Mac: open FaceTime and record a Voice Memo (the sensor treats that as a call),
or join a FaceTime link from an Android/Windows browser, or answer an iPhone call on the Mac.

## Jev: hearing what the phrase rules miss

The phrase rules catch the obvious wording ("gift cards", "don't tell"). With a key, every
finished sentence of the call also goes to [Jev](https://openrouter.ai/typesafe), a decision
model that answers ten yes/no questions ("the speaker asks for money", "the speaker asks for
secrecy", …) in about 300–500 ms with a calibrated probability each. That is how *"I'm a bit short
until my pension clears, could you help me out?"* becomes **asked for money** with no keyword in
it. Jev returns numbers only; nothing it produces is shown to the senior as text.

```bash
echo 'OPENROUTER_API_KEY=sk-or-...' > .env     # Jev via OpenRouter (the .env file is git-ignored)
set -a; source .env; set +a; python server.py
```

`TYPESAFE_API_KEY` works the same way against TypeSafe's own API. Without a key the rules run alone.
Labels Jev added show a small "·jev" tag on the call. Cost: about $0.00002 per sentence.

**Jev also judges the whole relationship.** Every 2 s during a call (and the moment a new warning
sign lands, and once more when the call ends) Jev reads the caller's history from the journal as
evidence (days known, calls per week and their length, late-night calls, the warning signs in
order, the amounts asked, payments made; never any words) and answers: how likely is fraud, is the
caller steering toward money, isolating her, are the asks escalating, and which scam pattern this
fits. The verdict sits on the caller's card ("Jev: 97% fraud · a romance scam") and, when a payment
is attempted, becomes the long-term component of the score with the rule-based ladder as its floor,
so a Jev outage never weakens the rules. `ELDERSHIELD_ASSESS_EVERY_S` changes the interval. Alerts stay on screen until she presses **Got it**; a newer alert replaces an older one.

When that judgment crosses a line during a call, she gets an alert of its own, once per call:
*"This call fits how romance scams work (96% sure). Daniel has known you 20 days, called 6 times
this week, calls late at night, asked you to keep things from your family, asked for money on 3
different days…"* The pattern picks the wording (romance, bank/tech-support, investment,
family-emergency, or just "a serious concern"); the facts come from the journal. So the scam
alert no longer depends on a phrase match: Jev also reads through speech-to-text errors ("target
give cards", "by coin", "any desk"), where the phrase rules caught 6 of 11 garbled test lines and
Jev 11 of 11.

## The alert, and "Send anyway"

| Score | Result |
|---|---|
| under 40 | sends |
| 40–69 | paused; "Send anyway" works at once |
| 70+ | paused; while a call is live, "Send anyway" waits until it ends |

"Send anyway" also waits whenever a remote-control app is running, at any score, because someone
else may be holding the mouse. A release works once, for that exact payment.

What adds to the score: a live call +15; remote control running +35 (earlier today +15); money,
gift cards or crypto asked on a call in the last day +35; a caller's long-term pattern +15
(isolating), +30 (asking), +40 (escalating); and the payment itself (wire +20, new payee +10).

## Privacy, and consent

- Everything stays in `eldershield_state.db` on this computer; **Reset** wipes it.
- The listener keeps no audio and no transcript: the daemon stores the warning-sign label and the
  sentence it was heard in (`ELDERSHIELD_SNIPPETS=0` keeps labels only), with long numbers removed.
- Listening is opt-in (`--listen`). Recording or monitoring calls needs everyone's consent in
  California and about a dozen other states; for the demo, use consenting teammates, and get legal
  advice before anyone else uses it.
- The server answers only its own page: a foreign `Origin` or a non-local `Host` gets a 403.

## Tests

```bash
playwright install chromium   # once, for the browser checks
python test_e2e.py            # starts its own server; needs port 8777 free
```

27 checks: the four moments (call, remote control, both, neither), "Send anyway" rules, the journal
(calls open and close, what was heard, snippets without numbers, live alerts once), the three-week
romance track and its effect on a payment, the origin lock, and real-browser checks of the stall,
the unlock and the memory panel.

## Files

- `server.py`: the daemon: device state, call journal, the long-term track, scoring, the page's API
- `device_watch.py`: macOS sensor: calls, caller, remote control; starts the listener; shows alerts
- `macos/Listen.swift`: hears the call and transcribes it on-device (built on first use)
- `macos/Warning.swift`: the alert window screen sharing can't see
- `index.html`: the bank page with ElderShield's alert, and "What ElderShield remembers"
- `demo_history.py`, `demo/romance_call.txt`: the three-week story and the live call for the demo
- `test_e2e.py`: the suite above

The earlier email version (Gmail extension, inbox watcher, multi-panel simulator) is on the
`main-before-oct24-afternoon` branch.
