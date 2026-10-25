# ElderShield — a payment guardian with a memory

ElderShield runs on an older adult's Mac, remembers who has been calling her and what they have
been asking for, and steps in at the one moment that matters: when money is about to move. It is
built for the slow scams, the ones that take weeks, and for the people she chooses to let in.

## Why this exists

Fraud against older adults is now one of the largest transfers of wealth in America, and most of
it is never reported.

- The FTC's report to Congress ([*Protecting Older Consumers 2025–2026*](https://www.ftc.gov/system/files/ftc_gov/pdf/2026-older-adults-report-10192026.pdf),
  October 2026) puts the **true cost of fraud to older adults in 2025 at $13.3 billion to
  $119.5 billion**. Reported losses alone reached $3 billion, five times the 2020 figure, and 6% of
  reports — losses of $100,000 or more — account for 70% of the money.
- The FBI's [2025 Internet Crime Report](https://www.ic3.gov/AnnualReport/Reports/2025_IC3Report.pdf)
  counts **$7.75 billion** reported by people over 60, up 59% in a year; an average loss of
  **$38,500**; more than 12,400 people who each lost over $100,000. Investment scams are the
  costliest category at $3.5 billion.
- AARP's [February 2026 survey](https://www.aarp.org/press/releases/2026-02-03-Romance-Scams-2026.html):
  **one in ten adults over 50** — about 11 million people — has been asked for money or crypto by
  someone they believed was a romantic partner. **55% of those who lost money told no one.**

Behind the numbers is a pattern that every filter misses. A wrong number becomes a friend, then a
sweetheart. Calls get longer and later. "Don't tell your daughter, she wouldn't understand." Then a
hospital bill, a customs fee, a once-in-a-lifetime investment, and the savings of a lifetime wired in
an afternoon. Spam filters and bank fraud models see day nineteen in isolation and see a normal
transfer. The victim sees a relationship. The family finds out when the money is gone, if at all,
because shame keeps most victims silent.

The scam works by isolating her. ElderShield works by remembering for her, and by keeping the people
she trusts close.

## What it does

1. **Watches the moment.** It knows when she is on a FaceTime, Zoom, WhatsApp or phone call, with
   whom, and whether a remote-control tool such as AnyDesk is running on her computer.
2. **Keeps a journal.** Who called, when, for how long, and — with listening switched on — the
   warning signs heard: loving words from a new contact, excuses not to meet, requests for secrecy,
   for money, gift cards, crypto or a one-time code. Only the flagged sentence is kept, with long
   numbers removed. Never the call.
3. **Steps in when money moves.** Every caller is tracked over weeks against the romance-scam ladder
   (getting to know you → love-bombing → isolating you → asking for money → escalating). When she
   sends a payment, ElderShield weighs the moment and the history together and, if they add up,
   pauses it with an alert in plain words: *"Wait — before you send $8,500. Daniel, someone you've
   known for 20 days, has been asking for more and more money."* If someone may be watching her
   screen, the alert appears in a window that screen sharing cannot capture, and the shared screen
   shows only a "Verifying…" stall.
4. **Tells the people she has chosen, and no one else.** She adds a daughter or a neighbour on her
   own page, hands them a six-letter code, and decides how much they hear: paused payments only, or
   warnings heard on calls as well. Their page updates the moment a payment is paused, and one press
   — *"I've seen this, I'm calling her"* — appears on her screen as *Sarah is calling you*. She can
   remove anyone at any time, and their page goes quiet in the same instant.

## How it decides

- **The decision is fixed code.** A payment's score is a sum of weighted facts (a live call, remote
  control, a request for money on a call today, a caller's long-term pattern). No model sits in that
  loop, so nothing a scammer says can talk the system into anything.
- **Two layers of hearing.** Phrase rules are the floor and work offline. [Jev](https://openrouter.ai/typesafe),
  a decision model, hears every finished sentence and answers ten yes/no questions with calibrated
  probabilities in a few hundred milliseconds, which is how *"I'm a bit short until my pension
  clears, could you help me out?"* is recognised as a request for money without a keyword in it.
  Every two seconds during a call, Jev also judges the whole relationship from the journal's counts
  and labels — never the words — and that judgment feeds the score with the rules as its floor.
- **Nothing she reads is generated.** Every sentence shown to her was written and reviewed by a
  person. Models supply numbers; the code chooses the words.
- **Her agency comes first.** She decides who is told, what they hear, and for how long. "Send
  anyway" is always available once nobody else may be holding the mouse or the line.

## Architecture

The journal, the payments, Jev's judgments and her circle live in a [SpacetimeDB](https://spacetimedb.com)
module ([`spacetimedb/src/index.ts`](spacetimedb/src/index.ts)). Its reducers are the only way to
write, and only the daemon's own identity may. Her family's page subscribes to views the module
computes per identity, so the question "what may this person see" is answered inside the database,
not in a web page, and a removal takes effect in the same transaction.

| Part | Role |
|---|---|
| `spacetimedb/` | The data model and every write path: journal, payments, releases, judgments, household, trusted people, family alerts; per-identity views |
| `server.py` | The daemon on her Mac: device state, the journal, the long-term track, scoring, her page's API |
| `device_watch.py` | The macOS sensor: live calls and callers, remote-control tools, the capture-proof alert window; launches the listener |
| `macos/Listen.swift` | Hears the other side of the call through a system-audio tap and transcribes it on-device |
| `jev.py` | Jev: the ten sentence-level questions and the call-level judgment |
| `index.html` | Her page: the bank form ElderShield guards, the alert, the journal, her circle |
| `family/` | Her circle's page: React on the SpacetimeDB client SDK |

Built with SpacetimeDB, Jev (TypeSafe, via OpenRouter), Apple's on-device speech recognition,
FastAPI and React. Designed by Aashish Sunar; built at Cal Hacks 13.0 with Claude Code as the pair
programmer.

## Run (macOS)

```bash
pip install -r requirements.txt
curl -sSf https://install.spacetimedb.com | sh          # the SpacetimeDB CLI, once
(cd family && npm install)                                # her circle's page, once
./start.sh                                                # everything, in order, with a check at each step
```

`start.sh` brings up the database, publishes the module, starts the daemon, the sensor (with
listening on) and the family page, then verifies the listener end to end by speaking a test sentence
through the Mac and showing what it transcribed. `./start.sh --watch` does the same and then
supervises the system, restarting any part that stops within five seconds. `./start.sh --check`
only checks; `./start.sh --stop` stops the application (the database keeps running); `./drill.sh`
is the resilience drill: it stops each component in turn and confirms recovery.

**Caller names** come from the Mac's call history, which macOS protects with Full Disk Access.
Grant it to Terminal (System Settings → Privacy & Security → Full Disk Access, then reopen
Terminal) and start ElderShield from a Terminal window; `start.sh` reports whether names will
resolve. A number not in Contacts appears as "Caller ending 4321". For a rehearsal,
`ELDERSHIELD_CALLER=Daniel ./start.sh` names every call Daniel.

**Jev** needs a key in `.env` (git-ignored): `OPENROUTER_API_KEY=sk-or-...` (or `TYPESAFE_API_KEY`
against TypeSafe's own API). Without one, the phrase rules run alone. Cost is about $0.00002 per
sentence.

Each part can also be run by hand:

```bash
spacetime start                                           # the database
spacetime publish eldershield --server local              # once, and after editing the module
python server.py                                          # the daemon → http://127.0.0.1:8777
python device_watch.py --listen                           # the sensor; without --listen, calls are detected but not heard
cd family && npm run dev                                  # her circle's page → http://127.0.0.1:5174
```

`spacetime publish` saves the token the daemon uses (`~/.config/spacetime/cli.toml`, or set
`SPACETIME_TOKEN`). `SPACETIME_URL` and `SPACETIME_DB` point the daemon at another server, such as
Maincloud, so her circle can reach it from anywhere; `ELDERSHIELD_NAME` is how her circle sees her
named. Listening asks macOS once for System Audio Recording and Speech Recognition; without
`--listen` the sensor needs no permissions at all.

## The demo

1. Click **Load 3-week story**. Daniel's card fills in: 13 calls in 20 days, later and longer, every
   rung of the ladder, and the flagged sentences in the journal.
2. Add **Sarah, daughter** under *People I've chosen to tell*. Open http://127.0.0.1:5174 in a
   private window and enter her code.
3. Start the call. Either a real FaceTime call to the Mac, or the rehearsal mode, which plays the
   lines in `demo/romance_call.txt` every six seconds as if heard:
   ```bash
   python device_watch.py --pretend facetime --caller Daniel --script demo/romance_call.txt
   ```
   Alerts only she can see appear as the warning signs land: *"They just asked you for money. You
   don't have to decide on this call."*
4. Send the $8,500 wire. It scores 100: the live call, the request a minute ago, the three-week
   pattern. Her screen shows the stall; the truth is in the private window; Sarah's page shows the
   paused payment within a second. Sarah presses **I've seen this — I'm calling her**, and
   Margaret's screen says so.
5. End the call, click **I've hung up — show me**: the alert offers **Don't send**, with **Send
   anyway** now available.

The listener hears the *other side* of a call, through the Mac's audio output. To rehearse the
screen-sharing part, start a QuickTime screen recording while an alert is up: the recording shows
the stall and not the alert.

## Her circle

The usual "family dashboard" watches the older adult. This one is hers.

- Nobody can add themselves. Nothing is shared until she adds someone, and the code she hands over
  binds to the first identity that uses it.
- She chooses what they hear: **paused payments only** (default) — one sentence each, with the first
  reason and never the account details — or **warnings on calls** as well.
- Never the calls, never the journal, never her bank.
- A family member's single press is checked by the database against her circle, recorded with their
  name, and shown to her within two seconds together with a private line: *you don't have to decide
  anything until you've talked to them.*

## The alert, and "Send anyway"

| Score | Result |
|---|---|
| under 40 | sends |
| 40–69 | paused; "Send anyway" works at once |
| 70+ | paused; while a call is live, "Send anyway" waits until it ends |

"Send anyway" also waits whenever a remote-control tool is running, at any score, because someone
else may be holding the mouse. A release is single-use and bound to that exact payment, checked and
spent in one database transaction.

What adds to the score: a live call +15; remote control running +35 (earlier today +15); money,
gift cards or crypto requested on a call in the last day +35; a caller's long-term pattern +15
(isolating), +30 (asking), +40 (escalating); the payment itself (wire +20, new payee +10).

## Privacy and consent

- Everything is decided on her computer. The journal lives in the SpacetimeDB database the daemon
  points at — local by default. Its tables are private; only the daemon's identity can write them;
  her family sees only the views she allows.
- No audio and no transcript are kept: a label, and the sentence it was heard in with long numbers
  removed (`ELDERSHIELD_SNIPPETS=0` keeps labels only).
- Listening is opt-in. Recording or monitoring calls requires every party's consent in California
  and about a dozen other states; use consenting participants, and obtain legal advice before wider
  use.
- The daemon answers only its own page: a foreign `Origin` or a non-local `Host` is refused.

## How we measure success

Success is money that did not leave, a family told early, and a normal life left undisturbed — not
alerts fired. The evaluation plan follows the metrics a fraud system should be held to: recall by
scam type, precision at the two thresholds, false alerts per normal call-hour, detection lead time,
calibration of Jev's probabilities against verified labels, correct attribution of calls and
payments, latency and recovery under failure, and whether she reached an independent person. Pressing
"Send anyway" is a behavioural outcome, not a label; calibration will use independently verified
outcomes, reported separately for scripted tests, red-team runs and consented pilots.

## Tests

```bash
playwright install chromium          # once, for the browser checks
python test_e2e.py                   # needs `spacetime start` running, and ports 8778 and 5175 free
python test_e2e.py --jev --restarts  # also one Jev check (key in .env), and a database restart under load
```

The suite publishes the module to its own database (`eldershield-test`), starts its own daemon and
its own copy of the family page, and drives both in a real browser, with Jev off so every check is
deterministic. 57 checks cover the four moments (call, remote control, both, neither), the "Send
anyway" rules, the journal, the three-week track and its effect on a payment, the origin lock, her
circle (hers to change, kept through Reset; a stranger gets no rows and cannot write), and the family
page: joining by code, a paused payment arriving live, one press reaching her window, warnings only
while she shares them, removal emptying the page.

## Roadmap

- **One timeline across channels:** messages, email and bank alerts feeding the same journal as calls.
- **After the alert:** an evidence pack she or her family can hand to a bank or the police — dates,
  pattern, amounts, never words — and guidance for the person who picks up the phone to call her.
- **Everywhere she talks:** Windows, iPhone and Android.
- **Built with users:** consented pilots with older adults and their families, with the evaluation
  above run on verified outcomes.
