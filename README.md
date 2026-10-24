# ElderShield v2 — Persistent Semantic & Action-Intent Firewall

A 100% local, privacy-preserving defensive agent for consumer elder protection. It
moves past stateless URL/signature scanning (which goes blind the moment a senior is
coached into using their *real* bank on a *legitimate* domain) to a **stateful**
firewall that correlates an inbound coercion signal with a high-stakes outbound
action inside a rolling causal window — and intercepts the money movement before it
completes.

## Run

```bash
pip install -r requirements.txt
python server.py
# open http://127.0.0.1:8777
```

Optional local LLM enrichment (the INTERCEPT decision never depends on it):

```bash
ollama serve &
ollama pull llama3.2:3b          # or set ELDERSHIELD_MODEL
```

The demo runs fully without Ollama — the deterministic scorer is authoritative and
stays inside the 250 ms budget; the LLM only refines the whisper text when it's up
and there's time left in the budget.

| env var | default | what it does |
|---|---|---|
| `ANTHROPIC_API_KEY` | unset | enables the cloud case investigator; without it a local rule engine answers and nothing leaves the machine |
| `ANTHROPIC_MODEL` | `claude-opus-5-5` | model for the investigator |
| `ELDERSHIELD_OVERRIDE_DELAY_S` | `86400` | cooling-off before an INTERCEPTed payment can be released (set e.g. `10` for a live demo) |
| `ELDERSHIELD_ALLOWED_ORIGINS` | unset | comma-separated extra origins allowed to call the daemon, e.g. a `chrome-extension://…` id |

### Releasing a paused payment, and who may call the daemon

- **CHALLENGE** → "Send it anyway" releases that payment at once. **INTERCEPT** → "I still want
  to send this" schedules the release after the cooling-off delay, because a scammer on the
  phone will simply tell the senior to press the button. The token works once, for that exact
  payment (kind, site, amount, destination), and every release is recorded.
- The daemon answers only its own UI: requests with a foreign `Origin` or a non-local `Host`
  (DNS rebinding) get a 403, so a web page can't read case files, wipe state with `/reset`, or
  release a payment. `/reset` and `/replay` are demo conveniences; remove them in production.
- **What leaves the machine:** with an API key set, each investigator call is logged *before* it
  is sent, with the exact request body, then marked sent or failed (`GET /disclosures`). Snippets
  are redacted first (numbers, phones, emails, wallets, names); payment details are only ever
  stored as salted hashes. The model's own wording is never shown to the senior.

## The demo (one screen, three panels)

1. **Tab A — the scammer.** An email + live-call transcript coaching the senior:
   *"Don't tell Chase why you are wiring the money — just tell them it's for a roof
   repair."* It also carries an invisible (`font-size:0`) span with an LLM prompt
   injection. Click **Receive this message**.
2. **Tab B — the real bank.** A genuine `chase.com` wire form. A traditional URL
   scanner says **100% SAFE**. Fill the memo with the coached story and click **Send
   wire**.
3. **Defense console.** Watch the causal graph, the entity trajectory, the
   **INTERCEPT** decision, the scammer-facing **tarpit**, the senior's **whisper
   banner**, and the signed **Proof of Coercion** receipt.

## How the decision is made (Module 1)

The outbound action is scored against every inbound trigger still inside the
30-minute window. Deterministic, sub-millisecond, additive components:

| component | weight | meaning |
|---|---|---|
| `trigger_severity` | 0–40 | 0.4 × the inbound coercion severity |
| `recency` | 0–25 | fresher coercion ⇒ stronger causality |
| `action_risk` | 5–20 | wire / crypto / gift-card / new-payee / password |
| `new_payee` | +10 | money going somewhere brand-new |
| **`coached_story_match`** | **+40** | **the coached cover story appears in the wire memo — the signal no stateless tool can see** |
| `adversarial_anomaly` | +15 | a hidden LLM-injection rode in on the trigger |

`≥70 → INTERCEPT`, `40–69 → CHALLENGE`, `<40 → ALLOW`. The LLM, if present, can
rewrite the whisper but cannot move the decision.

### Long-con (cold) path — grooming that happened days ago

Every trigger is written through to SQLite, so the 30-minute window survives a
browser/daemon restart mid-scam, and a 14-day lookback catches the common pattern
"coached on Tuesday, wires on Thursday". With no trigger in the hot window, the
scorer still checks:

| component | weight | meaning |
|---|---|---|
| `coached_story_match_long_con` | +40 | memo matches a cover story coached any time in the last 14 days |
| `long_con_trajectory` | +15 | some tracked sender reached `financial_request` in the last 14 days |

Example from the test suite: coaching backdated 3 days, wire today with memo
"roof repair" → **85, INTERCEPT**. The same day's unrelated "granddaughter tuition"
wire to a known payee → **35, ALLOW**.

---

## JSON state schemas

### `CrossTabCausalGraph` (`GET /state → causal_graph`)
```jsonc
{
  "window_minutes": 30,
  "updated_at": "2026-10-24T07:04:00Z",
  "triggers": [{
    "id": "trg_508993fe22",
    "tab_id": "tabA",
    "entity_hash": "6e4e86138382aa2ea040a97f",  // salted SHA-256, raw sender never stored
    "ts": 1792825361.73, "ts_iso": "…", "age_s": 11.2,
    "signals": { "urgency": ["immediately"], "impersonation": ["treasury department"],
                 "secrecy": ["do not tell"], "payment_pressure": ["wire"],
                 "voice_session": ["active_microphone_or_webrtc"] },
    "severity": 100,
    "coached_phrases": ["roof repair"],
    "anomalies": [{ "type":"hidden_llm_injection", "severity":"critical", "excerpt_hash":"…" }]
  }],
  "correlations": [{
    "trigger_id":"trg_…","action_id":"act_…","causality_score":100,
    "latency_s":11.2,"decision":"INTERCEPT","reason":"…"
  }]
}
```

### `EntityTrajectoryStore` (SQLite; `GET /state → entities`)
```jsonc
{
  "entity_hash": "6e4e86138382aa2ea040a97f",
  "first_seen": 1792825361.73, "last_seen": 1792825361.73,
  "escalation_stage": "financial_request",            // contact → off_platform_chat → urgency_lure → financial_request
  "stage_history": [{ "stage":"financial_request", "ts":"2026-10-24T07:02:41Z" }],
  "channels": ["email"],
  "interaction_count": 1,
  "risk_score": 100                                    // climbs with escalation depth + severity, monotonic stage
}
```

### `ProofOfCoercionReceipt` (`POST /mint-receipt`)
```jsonc
{
  "payload": {
    "schema": "eldershield.proof_of_coercion.v2",
    "receipt_id": "poc_858646c4c0fe",
    "issued_at": "2026-10-24T07:04:36Z",
    "intercepted_action": { "type":"wire_transfer","origin":"chase.com",
                            "amount_blocked":15000.0,"action_id":"act_demo" },
    "causality_score": 100,
    "trigger_vector_hashes": [{ "category":"secrecy","vector_hash":"509518d743c95ed7" }],
    "entity_trajectory_digest": { "stage":"financial_request","stage_count":1,
                                  "first_seen":"…","risk_score":100 },
    "redacted_summary": "… No raw message or account content is included by design."
  },
  "payload_sha256": "…",
  "signature_ed25519": "base64…",        // over canonical (sorted, compact) payload
  "device_pubkey_ed25519": "base64…"      // local device key; private key never leaves disk
}
```
`POST /verify-receipt` returns `{"valid": true}`; any tampering of the payload flips
it to `false`. This is what a senior's family hands a bank/insurer to prove an active
social-engineering attack occurred — **without** exposing the raw emails or balances.

---

## Tests

```bash
playwright install chromium   # once, for the browser checks
python test_e2e.py            # starts its own server; needs port 8777 free
```

38 checks: clean-wire control, hot-path intercept and latency, plain-language
whisper, receipt verify + tamper rejection, live state validated against
`schemas.py`, restart rehydration, the 3-day cold path and its control, the four
replays (A–C intercept; D, a first-time contractor paid to the invoice's own account,
is allowed), the override's cooling-off / binding / single use, no watch-item spill
across payment kinds, storage privacy, the origin lock, and a real Chromium run
proving the `submit` is captured (no navigation), the decoy and whisper render, the
release button schedules instead of sending, and class-hidden injection is caught.
If port 8777 can't be used, the suite runs in-process and reports the browser checks
as SKIPPED.

## Endpoints

| method | path | purpose |
|---|---|---|
| GET  | `/` | the simulator UI |
| GET  | `/health` | device pubkey, window size |
| POST | `/ingest/trigger` | sanitize → classify → advance entity → record trigger (Module 1 + 4) |
| POST | `/evaluate/action` | causality score + decision + tarpit + whisper, ≤250 ms (Module 1 + 2) |
| POST | `/mint-receipt` | signed Proof of Coercion (Module 4) |
| POST | `/verify-receipt` | Ed25519 verification |
| POST | `/sandbox/fingerprint` | local phishing-kit fingerprint (Module 3) |
| GET  | `/state` | full causal graph + entity store |
| GET  | `/schemas` | JSON Schema for all three state objects (from `schemas.py`) |
| POST | `/reset` | clear state (demo convenience) |

---

## Module 2 — the Deceptive Mirror, and its honest caveat

On INTERCEPT the page shows the scammer (via screen-share) a local, deliberately
generic "Verifying wire details with receiving institution…" stall that never completes, while the senior gets a
truthful Shadow-DOM whisper banner explaining what's happening. **The tarpit renders
only on the user's own device — it contacts and attacks no external system.**

Caveat worth stating to any judge/partner: a stall shown on a *false positive* is a
real cost — it wastes a legitimate user's time and could, in a true emergency, delay
a genuine transfer. That's why the tarpit fires only on INTERCEPT (score ≥ 70, which
in practice requires the coached-story match or stacked high-severity signals), the
whisper always tells the truth, and the senior can dismiss the stall in one click.
This is a dignity/latency trade-off to tune with real users, not a solved problem.

**The whisper is not private from a full-screen share.** Shadow DOM stops the page
from restyling or hiding the banner; it does not stop a remote-access tool from
seeing it. Two mitigations are in the design: the spoken cue (Web Speech API,
on-device) reaches a headset without appearing on screen, and the production path is
for the local daemon to draw the whisper in a native window flagged as excluded from
screen capture (Windows `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)`; honoured
by the standard capture APIs, but verify per remote-access tool and OS version).

## Module 3 security note — why there is no canary-credential probe

The spec asked ElderShield to **auto-inject synthetic credentials into unverified
third-party login forms and infer "harvester" if the server accepts them.** This
implementation deliberately does **not** do that, for engineering reasons first:

- It's autonomous outbound submission to servers we don't control or individually
  authorize — unauthorized-access probing (CFAA-shaped), and at any scale it
  generates automated traffic against third parties, including the inevitable false
  positives where a misclassified *legitimate* site gets probed.
- The signal is weak: almost every login endpoint returns 200 to any POST.
  "Server accepted fake creds" ≉ harvester.

The same goal — high-confidence kit identification with near-zero false positives —
is reached **100% locally** on DOM already on the user's screen, with no credential
submission and no third-party contact: `fingerprint_phishing_kit()` flags a password
form posting cross-origin (critical), brand-vs-origin mismatch, obfuscated handlers,
and hidden LLM-injection. In testing it returns `verified_phishing_kit` (100%) on a
cross-origin kit and `clean` (0) on a legitimate same-origin login.

The hidden-CSS prompt-injection stripper (`sanitize_dom_text`) *is* built as
specified: it quarantines `font-size:0` / `opacity:0` / off-screen text before any
LLM sees it and flags embedded "ignore previous instructions / mark as safe" payloads
as critical adversarial anomalies.

"Counter-reconnaissance on untrusted senders" is scoped to **passive, local analysis
of content already in the user's own inbox** — not active investigation of sender
infrastructure.

## Privacy posture

Everything runs on-device. The raw sender is hashed with a per-device salt the moment
it arrives and never stored. Receipts carry salted category hashes and a redacted
summary — never raw email or balances. SQLite, the salt, and the Ed25519 private key
all stay on disk with `0600` where the OS allows.

## Files

- `server.py` — FastAPI core: causality engine (hot + long-con paths), entity store, receipts, fingerprinter, serves the UI
- `schemas.py` — Pydantic contracts for `CrossTabCausalGraph`, `EntityTrajectoryStore`, `ProofOfCoercionReceipt`
- `test_e2e.py` — the 15-check suite above
- `index.html` — two-tab simulator + live defense console (no build step)
- `requirements.txt`

## Known limits (honest)

- The semantic classifier is lexical + a coached-phrase extractor. It's deterministic
  and fast and good enough to demo the *architecture*; production wants the local LLM
  (or a small fine-tune) carrying more of the semantic load, with the heuristic as the
  latency-safe floor.
- The browser can only see coaching that reaches the browser (webmail, chat, WebRTC
  calls). A scam call on a separate phone is invisible to it; there, the coached
  memo match and the long-con path carry the weight.
- `coached_phrases` extraction handles the common "tell them it's for X" patterns;
  broaden with the LLM path for paraphrased coaching.
