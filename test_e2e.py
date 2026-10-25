"""
End-to-end check for ElderShield. It publishes the module to its own database (`eldershield-test`,
so the demo's `eldershield` is never touched), starts its own daemon on port 8778 and, for her
circle's page, its own Vite dev server on 5175, and drives both in a real browser:
    python test_e2e.py              # Jev off, so every check is deterministic
    python test_e2e.py --jev        # also one check of Jev hearing an ask with no keyword in it (key in .env)
    python test_e2e.py --restarts   # also kill and restart the SpacetimeDB server under everything; off by
                                    # default because that server is shared with whatever else is using it
Needs `spacetime start` running, `pip install -r requirements.txt`, `playwright install chromium`
once for the browser checks, and `npm install` in family/ for her circle's page.
"""

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
PORT, FAMILY_PORT = 8778, 5175
B = f"http://127.0.0.1:{PORT}"
FAMILY = f"http://127.0.0.1:{FAMILY_PORT}"
STDB = os.environ.get("SPACETIME_URL", "http://127.0.0.1:3000").rstrip("/")
DB = "eldershield-test"
SPACETIME = shutil.which("spacetime") or str(Path.home() / ".local/bin/spacetime")
VITE = HERE / "family/node_modules/.bin/vite"
LOGS = Path(tempfile.gettempdir()) / "eldershield-test"       # the daemon's and Vite's output, for a failed run
JEV, RESTARTS = "--jev" in sys.argv, "--restarts" in sys.argv
srv = vite = None


def http(url, body=None, headers=None, content_type="application/json"):
    """(status, body) for any request, including refused ones; the body decoded when it is JSON."""
    data = None if body is None else (body if isinstance(body, str) else json.dumps(body)).encode()
    req = urllib.request.Request(url, data=data, method="GET" if body is None else "POST",
                                 headers={"Content-Type": content_type, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            status, raw = r.status, r.read()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
    try:
        return status, json.loads(raw)
    except ValueError:
        return status, raw.decode(errors="replace")


def request(path, body=None, headers=None):
    return http(B + path, body, headers)


def call(path, body=None):
    return request(path, body)[1]


def device(call_app=None, remote=(), caller=None, private=False):
    call("/device/context", {"call_app": call_app, "caller": caller, "remote_access": list(remote), "private_window": private})


def wire(amount=8500, new_payee=True, account="987654321012", **extra):
    return call("/evaluate/action", {"origin": "chase.com", "action_type": "wire_transfer", "amount": amount,
                                     "new_payee": new_payee, "routing_number": "021000021", "account_number": account, **extra})


def heard(text, chunk=0, final=False):
    return call("/calls/transcript", {"chunk": chunk, "text": text, "final": final})["heard"]


def until(cond, timeout=5.0):
    """The first truthy value of cond() within timeout, else its last value."""
    t0 = time.time()
    while True:
        v = cond()
        if v or time.time() - t0 > timeout:
            return v
        time.sleep(0.2)


def eventually(page, js, timeout=10000):
    """True once the page's js is truthy, False if it isn't within timeout (ms)."""
    try:
        page.wait_for_function(js, timeout=timeout)
        return True
    except Exception:
        return False


def ping():
    try:
        return urllib.request.urlopen(STDB + "/v1/ping", timeout=2).status == 200
    except Exception:
        return False


def up(url, timeout, proc=None):
    """True once url answers; False if it doesn't in time, or proc exits first."""
    t0 = time.time()
    while time.time() - t0 < timeout:
        if proc is not None and proc.poll() is not None:
            return False
        try:
            urllib.request.urlopen(url, timeout=2)
            return True
        except Exception:
            time.sleep(0.1)
    return False


def port_free(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)   # as uvicorn does; else TIME_WAIT looks "busy"
    try:
        s.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def log(name):
    LOGS.mkdir(exist_ok=True)
    return open(LOGS / f"{name}.log", "a")


def die(msg):
    print("FAIL " + msg)
    sys.exit(2)


def start_daemon(jev_key=None):
    """The daemon under test: its own port and database, and Jev off unless a key is given."""
    env = {k: v for k, v in os.environ.items() if k not in ("OPENROUTER_API_KEY", "TYPESAFE_API_KEY")}
    env.update({"ELDERSHIELD_PORT": str(PORT), "SPACETIME_DB": DB, **(jev_key or {})})
    p = subprocess.Popen([sys.executable, str(HERE / "server.py")], cwd=HERE, env=env,
                         stdout=log("daemon"), stderr=subprocess.STDOUT)
    if not up(B + "/health", 20, p):
        p.terminate()
        raise RuntimeError(f"the daemon didn't come up on {B}; see {LOGS}/daemon.log")
    return p


def restart_daemon(jev_key=None):
    global srv
    srv.terminate()
    srv.wait(timeout=10)
    srv = start_daemon(jev_key)


def jev_key():
    """The Jev key from the environment or .env, as {name: key}; None without one."""
    env = dict(os.environ)
    try:
        for line in (HERE / ".env").read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                env.setdefault(k.strip(), v.strip().strip("'\""))
    except OSError:
        pass
    return next(({k: env[k]} for k in ("OPENROUTER_API_KEY", "TYPESAFE_API_KEY") if env.get(k)), None)


results, skipped = [], []


def ok(name, cond, extra=""):
    cond = bool(cond)
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))
    results.append(cond)
    return cond


# --- the pieces under test: a clean database, our own daemon, our own copy of her circle's page ---
shutil.rmtree(LOGS, ignore_errors=True)
if not ping():
    die(f"SpacetimeDB isn't answering at {STDB}: start it with `spacetime start` (or point SPACETIME_URL at it)")
for port in (PORT, FAMILY_PORT):
    if not port_free(port):
        die(f"port {port} is busy (another test run?): lsof -nP -iTCP:{port}")
if not Path(SPACETIME).exists():
    die("the spacetime CLI isn't installed: curl -sSf https://install.spacetimedb.com | sh")
pub = subprocess.run([SPACETIME, "publish", DB, "--server", "local", "--yes=all", "--delete-data=always",
                      "--module-path", "spacetimedb"], cwd=HERE, capture_output=True, text=True, timeout=300)
if pub.returncode != 0:
    die(f"couldn't publish the module to {DB}:\n{pub.stdout[-1500:]}{pub.stderr[-1500:]}")
print(f"published spacetimedb/ to {DB} (the demo's database is untouched); daemon on {B}, her circle's page on {FAMILY}")
try:
    srv = start_daemon()
except RuntimeError as e:
    die(str(e))
if VITE.exists():
    vite = subprocess.Popen([str(VITE), "--port", str(FAMILY_PORT), "--strictPort", "--host", "127.0.0.1"],
                            cwd=HERE / "family", env={**os.environ, "VITE_SPACETIME_DB": DB},
                            stdout=log("vite"), stderr=subprocess.STDOUT)

try:
    # 1) the moment: device signals
    call("/reset", {})
    r = wire()
    ok("nothing unusual: the payment goes through", r["decision"] == "ALLOW")
    device("FaceTime", ["AnyDesk"])
    r = wire(new_payee=False)
    ok("call + remote control intercepts even to an existing payee", r["decision"] == "INTERCEPT", r["score"])
    device(None, ["AnyDesk"])
    r = wire()
    status, _ = request("/override", {"action_id": r["action_id"]})
    ok("'Send anyway' is locked while remote control runs, even at medium risk",
       r["decision"] == "CHALLENGE" and r["locked"] and status == 409, f'{r["decision"]} {status}')
    call("/reset", {})
    device("FaceTime", private=True)
    since = time.time()
    r = wire()
    alerts = call(f"/device/alerts?after={since}")
    ok("during a call, even a medium-risk alert goes to the private window",
       r["decision"] == "CHALLENGE" and r["private_overlay"] and r["decoy"]
       and len(alerts) == 1 and alerts[0]["title"].startswith("Wait"), alerts)
    ok("the alert cursor is a timestamp (no lost alerts after a restart)",
       call(f"/device/alerts?after={alerts[0]['ts']}") == [])

    # 2) "Send anyway" for a high-risk payment
    call("/reset", {})
    device("FaceTime", ["AnyDesk"])
    paused = wire()
    status, _ = request("/override", {"action_id": paused["action_id"]})
    ok("'Send anyway' waits while the call is live", status == 409, status)
    device()
    tok = call("/override", {"action_id": paused["action_id"]})["override_token"]
    ok("the release doesn't fit a different payment", wire(amount=900, override_token=tok)["decision"] != "ALLOW")
    ok("the release works once, for that payment", wire(override_token=tok)["decision"] == "ALLOW")
    ok("…and only once", wire(override_token=tok)["path"] != "override")
    status, _ = request("/override", {"action_id": "act_unknown"})
    ok("unknown payment: 404", status == 404, status)

    # 3) the journal: calls and what was heard
    call("/reset", {})
    device("FaceTime", caller="Daniel")
    since = time.time()
    h = heard("Buy five hundred dollars in Target gift cards and read me the numbers.")
    h2 = heard("Buy five hundred dollars in Target gift cards and read me the numbers.")   # same chunk again
    ok("hearing 'gift cards' on a call is recorded once per chunk",
       [x["label"] for x in h].count("gift_cards") == 1 and h2 == [], (h, h2))
    alerts = call(f"/device/alerts?after={since}")
    ok("…and raises a live alert about gift cards (alerts are a list, newest first)",
       any("gift cards" in a["title"] for a in alerts) and alerts == sorted(alerts, key=lambda a: -a["ts"]), alerts)
    h = heard("Now read me the code you just got, it's 482913.", chunk=1)
    ok("snippets drop long numbers such as codes",
       any(x["label"] == "one_time_code" and "482913" not in x["snippet"] for x in h), h)
    calls = call("/state")["track"]["recent_calls"]
    ok("the call is in the journal, live, with the caller's name",
       calls and calls[0]["live"] and calls[0]["who"] == "Daniel", calls[:1])
    ok("…and carries what was heard, with its source",
       {(s["label"], s["source"]) for s in calls[0]["heard"]} >= {("gift_cards", "rules"), ("one_time_code", "rules")})
    device()
    calls = call("/state")["track"]["recent_calls"]
    ok("the call closes when it ends", not calls[0]["live"])
    # the Mac names a call in its history a moment after it connects, so the sensor's first guess
    # can be the previous caller; a correction early in the call moves the call and what was heard
    call("/reset", {})
    device("FaceTime", caller="Caller ending 3141")
    heard("My love, I need you to send money today.")
    device("FaceTime", caller="Daniel")
    calls, people = call("/state")["track"]["recent_calls"], call("/state")["track"]["contacts"]
    ok("an early correction of the caller moves the call, and what was heard, to the right person",
       calls[0]["who"] == "Daniel" and {h["label"] for h in calls[0]["heard"]} >= {"endearment", "money_request"}
       and all(c["name"] != "Caller ending 3141" for c in people), [c["name"] for c in people])
    device()

    # 4) the long-term track: a 3-week romance scam
    call("/demo/seed", {})
    people = {c["name"]: c for c in call("/state")["track"]["contacts"]}
    d = people.get("Daniel", {})
    ok("Daniel's three weeks read as an escalating money pattern",
       d.get("stage") == 5 and d.get("risk") == "high", d.get("stage_name"))
    ok("…with plain-words flags", any("Known for only" in f for f in d.get("flags", []))
       and any("keep things from your family" in f for f in d.get("flags", [])), d.get("flags"))
    ok("the daughter's weekly calls stay low risk", people.get("Sarah (daughter)", {}).get("risk") == "low")
    r = wire()
    ok("the history alone pauses a new-payee wire, naming Daniel",
       r["decision"] == "INTERCEPT" and "long_term_pattern" in r["components"]
       and any("Daniel" in x for x in r["reasons"]), r["components"])
    device("FaceTime", caller="Daniel")
    heard("The hospital needs the money today. Please send eight thousand five hundred dollars.", chunk=5)
    r = wire()
    ok("during his call, after he asks again: 100 and locked",
       r["score"] == 100 and r["locked"] and "money_asked_on_call" in r["components"], r["reasons"])
    device()
    call("/reset", {})
    ok("Reset clears the journal", call("/state")["track"]["contacts"] == [])

    # 5) only the page itself may call the daemon
    status, _ = request("/reset", {}, headers={"Origin": "https://evil.example"})
    ok("a web page cannot call the daemon", status == 403, status)
    status, _ = request("/state", headers={"Host": f"evil.example:{PORT}"})
    ok("DNS-rebinding host is refused", status == 403, status)

    # 6) her circle is hers: who, how much, and under what name; it outlives Reset; strangers get nothing
    fam = call("/family/people", {"name": "Sarah", "relation": "daughter"})
    sarah = next((p for p in fam["people"] if p["name"] == "Sarah"), {})
    ok("she adds someone and gets a six-letter code to hand them; nobody has joined yet",
       len(sarah.get("code", "")) == 6 and sarah["code"].isalnum() and not sarah["joined"]
       and sarah["relation"] == "daughter" and fam["share_level"] == "payments", fam)
    fam = call("/family/name", {"name": "Peggy"})
    ok("she chooses how her circle sees her named", fam["elder_name"] == "Peggy")
    fam = call("/family/share", {"level": "warnings"})
    ok("…and how much they hear", fam["share_level"] == "warnings")
    call("/reset", {})
    s = call("/state")
    ok("Reset clears the journal but keeps her circle, her name and her choice",
       s["track"]["contacts"] == [] and any(p["id"] == sarah["id"] for p in s["family"]["people"])
       and s["family"]["elder_name"] == "Peggy" and s["family"]["share_level"] == "warnings", s["family"])
    call("/family/share", {"level": "payments"})
    fam = call("/family/people/remove", {"id": sarah["id"]})
    ok("she can take someone out again", fam["people"] == [])
    sql = f"{STDB}/v1/database/{DB}/sql"
    status, body = http(sql, "SELECT * FROM my_alerts", content_type="text/plain")
    ok("a stranger asking the database for her alerts gets no rows", status == 200 and body[0]["rows"] == [], (status, body))
    status, body = http(sql, "SELECT * FROM family_alert", content_type="text/plain")
    ok("…and can't read the tables themselves", status == 400 and "private" in body, (status, body))
    status, body = http(f"{STDB}/v1/database/{DB}/call/start_call", ["call_stranger", "unknown", "FaceTime", time.time(), "[]"])
    ok("…and can't write the journal (the module refuses: 530)", status == 530 and "only ElderShield" in body, (status, body))
    status, body = http(f"{STDB}/v1/database/{DB}/call/add_trusted_person", ["Mallory", "", time.time()])
    ok("…or add themselves to her circle", status == 530, (status, body))

    # 7) the browser: her page, then her circle's page
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        sync_playwright = None
    browser = None
    if sync_playwright is not None:
        pw = sync_playwright().start()
        try:
            browser = pw.chromium.launch()
        except Exception as e:
            pw.stop()
            print(f"NOTE: {str(e).splitlines()[0]}")
    if browser is None:
        skipped += ["her page in a browser (7 checks): pip install playwright && playwright install chromium",
                    "her circle's page in a browser (16 checks): same"]
    else:
        alert_js = "document.getElementById('es-alert').shadowRoot.getElementById('anyway')"
        page = browser.new_page(viewport={"width": 1280, "height": 1100})
        call("/reset", {})
        device("FaceTime", ["AnyDesk"], private=True)
        page.goto(B)
        page.click("button[type=submit]")
        page.wait_for_selector("#decoy", state="visible")
        ok("browser: with someone watching and the private window, the page shows only the stall",
           page.evaluate("!document.getElementById('es-alert')"))

        call("/reset", {})
        device("FaceTime", ["AnyDesk"])
        page.goto(B)
        page.click("button[type=submit]")
        page.wait_for_selector("#es-alert")
        locked = page.evaluate(alert_js + ".disabled")
        device()
        page.wait_for_function("!" + alert_js + ".disabled", timeout=8000)
        page.evaluate(alert_js + ".click()")
        page.wait_for_function("document.getElementById('actionOut').textContent.startsWith('Sent ')", timeout=6000)
        ok("browser: 'Send anyway' waits for the call to end, then sends once", locked)
        ok("browser: the form never submits natively (no navigation)", page.url.rstrip("/") == B)

        call("/reset", {})
        page.goto(B)
        page.click("text=Load 3-week story")
        page.wait_for_selector(".person.high")
        page.wait_for_timeout(400)
        text = page.inner_text("aside")
        page.screenshot(path=str(LOGS / "three-week-story.png"), full_page=True)
        ok("browser: the 3-week story shows Daniel's card and the call journal",
           "Daniel" in text and "escalating" in text and "hospital" in text.lower())

        # her circle, from her page
        call("/reset", {})
        page.goto(B)
        page.wait_for_function("!document.getElementById('circle').innerText.includes('Loading')", timeout=15000)
        page.fill("#circleName", "Sarah")
        page.fill("#circleRelation", "daughter")
        page.click("#circleForm button")
        page.wait_for_selector(".trusted .code", timeout=10000)
        code = page.inner_text(".trusted .code").strip()
        ok("browser: adding someone from her page shows the code to hand over", len(code) == 6, code)
        has_select = page.locator("#circleShare select").count() == 1
        if has_select:
            page.select_option("#circleShare select", "warnings")
        ok("browser: the share-level choice appears once someone is in the circle, and changes what they hear",
           has_select and until(lambda: call("/state")["family"]["share_level"] == "warnings"))
        page.click(".trusted button.link")
        page.wait_for_function("document.querySelectorAll('.trusted').length === 0", timeout=10000)
        ok("browser: remove works from her page", call("/state")["family"]["people"] == [])
        call("/family/share", {"level": "payments"})
        page.goto("about:blank")          # her page polls /state; the checks below want it closed

        if vite is None or not up(FAMILY, 30, vite):
            skipped.append("her circle's page in a browser (16 checks): " + (
                "run `npm install` in family/" if vite is None else f"Vite didn't come up on {FAMILY}; see {LOGS}/vite.log"))
        else:
            call("/reset", {})
            call("/demo/seed", {})        # Daniel's history alone pauses a wire: that is what her circle hears about
            fam = call("/family/people", {"name": "Sarah", "relation": "daughter"})
            sarah = next(p for p in fam["people"] if p["name"] == "Sarah")
            elder = fam["elder_name"]
            ctx = browser.new_context(viewport={"width": 480, "height": 860})   # a fresh context is a fresh identity
            fpage = ctx.new_page()
            errors = []
            fpage.on("pageerror", lambda e: errors.append(str(e)))
            fpage.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
            fpage.goto(FAMILY)
            fpage.wait_for_selector("text=Enter the code she gave you", timeout=15000)
            ok("family: a fresh identity sees the join form and no alerts", fpage.locator(".alert").count() == 0)
            fpage.fill("input", "ZZZZZZ")
            fpage.click("button:has-text('Join her circle')")
            fpage.wait_for_selector(".err", timeout=10000)
            ok("family: a wrong code is refused, in the module's words",
               "not one she has given out" in fpage.inner_text(".err"), fpage.inner_text(".err"))
            fpage.fill("input", sarah["code"])
            fpage.click("button:has-text('Join her circle')")
            fpage.wait_for_selector(".who", timeout=10000)
            who = fpage.inner_text(".who")
            ok("family: her code joins, under her name", elder in who and "Sarah" in who, who)
            ok("family: her page shows Sarah as joined",
               until(lambda: any(p["id"] == sarah["id"] and p["joined"] for p in call("/state")["family"]["people"])))

            t0 = time.time()
            r = wire()
            arrived = eventually(fpage, "document.querySelectorAll('.alert').length > 0")
            dt = time.time() - t0
            text = fpage.locator(".alert").first.inner_text() if arrived else ""
            ok(f"family: the paused payment reaches Sarah's page live, without a reload ({dt:.1f} s)",
               arrived and r["decision"] == "INTERCEPT" and "paused a $8,500" in text and dt < 10, (r["decision"], text))
            ok("family: in a sentence with the reason, never the account details",
               "Daniel" in text and "987654321012" not in text and "021000021" not in text, text)
            fpage.locator(".alert").first.locator("button").click()
            fpage.locator(".alert").first.locator(".ack").wait_for(timeout=10000)

            def acked():
                st = call("/state")
                return st if any(a["acknowledged_by"] == "Sarah" for a in st["family"]["alerts"]) else None
            s = until(acked)
            ok("family: one press records who is calling, on her page", bool(s))
            ok("family: …and she gets a private line that Sarah is calling",
               s and any("Sarah has seen this" in a["title"] for a in s["alert"]), s and s["alert"])

            device("FaceTime", caller="Daniel")
            heard("Buy five hundred dollars in Target gift cards and read me the numbers.", chunk=9)
            time.sleep(1.5)
            ok("family: warnings heard on calls stay with her by default", fpage.locator(".alert.warning").count() == 0)
            call("/family/share", {"level": "warnings"})
            shown = eventually(fpage, "document.querySelectorAll('.alert.warning').length > 0")
            ok("family: …until she chooses to share them, live",
               shown and any("gift cards" in t for t in fpage.locator(".alert.warning").all_inner_texts()))
            call("/family/share", {"level": "payments"})
            ok("family: …and leave again the moment she changes her mind",
               eventually(fpage, "document.querySelectorAll('.alert.warning').length === 0"))
            device()
            ok("family: no browser errors on her circle's page", not errors, errors[:3])

            # the daemon restarts: her circle and her name are in the database, Sarah's identity in her browser
            restart_daemon()
            fam = call("/state")["family"]
            ok("restart: her name and her circle survive a daemon restart",
               fam["elder_name"] == elder and any(p["id"] == sarah["id"] and p["joined"] for p in fam["people"]), fam)
            fpage.reload()
            fpage.wait_for_selector(".who", timeout=15000)
            ok("restart: Sarah's browser is still in the circle, no code needed again",
               "Sarah" in fpage.inner_text(".who") and fpage.locator(".alert").count() >= 1)
            n0 = fpage.locator(".alert").count()
            t_before = time.time()
            wire()
            arrived = eventually(fpage, f"document.querySelectorAll('.alert').length > {n0}")
            fpage.locator(".alert").first.locator("button").click()
            got = until(lambda: any("Sarah has seen this" in a["title"] for a in call(f"/device/alerts?after={t_before}")), timeout=8)
            ok("restart: with her page closed, the private window still hears that Sarah is calling", arrived and got)

            if RESTARTS:
                pids = subprocess.run(["lsof", "-nP", "-tiTCP:3000", "-sTCP:LISTEN"], capture_output=True, text=True).stdout.split()
                for pid in pids:
                    subprocess.run(["kill", pid])
                ok("restart: the database stopped", until(lambda: not ping(), timeout=15), pids)
                subprocess.Popen([SPACETIME, "start", "--listen-addr", "127.0.0.1:3000", "--non-interactive"],
                                 stdout=log("spacetime"), stderr=subprocess.STDOUT, start_new_session=True)
                t0 = time.time()
                ok("restart: the database is back", until(ping, timeout=60), f"{time.time() - t0:.0f} s")

                def state_or_none():
                    status, body = request("/state")
                    return body if status == 200 else None
                st = until(state_or_none, timeout=15)
                ok("restart: the daemon recovered by itself and the journal persisted",
                   st and any(c["name"] == "Daniel" and c["calls"] >= 12 for c in st["track"]["contacts"]),
                   st and [(c["name"], c["calls"]) for c in st["track"]["contacts"]])
                ok("restart: her circle persisted too",
                   st and any(p["id"] == sarah["id"] and p["joined"] for p in st["family"]["people"]))
                n1 = fpage.locator(".alert").count()
                wire()
                ok("restart: Sarah's page reconnected on its own and shows the new alert live",
                   eventually(fpage, f"document.querySelectorAll('.alert').length > {n1}", 20000))
            else:
                skipped.append("database restart (5 checks): pass --restarts; it kills and restarts the SpacetimeDB "
                               "server everything else on this machine is using")

            call("/family/people/remove", {"id": sarah["id"]})
            ok("family: taken out of her circle, Sarah's page drops to the join form live, alerts gone",
               eventually(fpage, "document.body.innerText.includes('Enter the code she gave you') "
                                 "&& document.querySelectorAll('.alert').length === 0"))
            ctx.close()
        browser.close()
        pw.stop()

    # 8) Jev, if asked: an ask with no keyword in it, heard by the model and written as its own signal
    key = jev_key() if JEV else None
    if not JEV:
        skipped.append("jev: an ask with no keyword in it is heard by Jev (pass --jev, with OPENROUTER_API_KEY "
                       "or TYPESAFE_API_KEY in .env)")
    elif not key:
        skipped.append("jev: an ask with no keyword in it is heard by Jev (no OPENROUTER_API_KEY or "
                       "TYPESAFE_API_KEY in .env or the environment)")
    else:
        restart_daemon(key)
        call("/reset", {})
        device("FaceTime", caller="Daniel")
        rules = heard("I am a bit short until my pension clears could you help me out", chunk=1, final=True)
        t0 = time.time()
        found = until(lambda: any(s["label"] == "money_request" and s["source"] == "jev"
                                  for c in call("/state")["track"]["recent_calls"][:1] for s in c["heard"]), timeout=5)
        ok(f"jev: 'a bit short until my pension clears' is heard as asking for money, by Jev alone, in {time.time() - t0:.1f} s",
           rules == [] and found, (rules, call("/state")["jev"]))
        device()
except Exception:
    traceback.print_exc()
    results.append(False)
finally:
    for p in (srv, vite):
        if p:
            p.terminate()
            try:
                p.wait(timeout=10)          # so the ports are free again the moment this exits
            except subprocess.TimeoutExpired:
                p.kill()

for name in skipped:
    print("SKIP " + name)
print(f"\n{sum(results)}/{len(results)} passed" + (f", {len(skipped)} skipped" if skipped else ""))
if not all(results):
    print(f"logs: {LOGS}")
sys.exit(0 if all(results) else 1)
