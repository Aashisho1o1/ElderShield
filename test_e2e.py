"""
End-to-end check for ElderShield. Starts its own server, so port 8777 must be free:
    python test_e2e.py
If the port can't be used it runs in-process, and the browser checks are reported as SKIPPED.
"""

import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
B = "http://127.0.0.1:8777"
client = None
srv = None


def can_bind_port():
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)   # as uvicorn does; else TIME_WAIT looks "busy"
    try:
        s.bind(("127.0.0.1", 8777))
        s.close()
        return True
    except Exception:
        return False


def start_server():
    global client, srv
    if can_bind_port():
        p = subprocess.Popen([sys.executable, str(HERE / "server.py")], cwd=HERE,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(50):
            try:
                urllib.request.urlopen(B + "/health", timeout=2)
                srv = p
                return
            except Exception:
                time.sleep(0.1)
    print("NOTE: port 8777 unavailable, running in-process (browser checks will be skipped)")
    from fastapi.testclient import TestClient
    sys.path.insert(0, str(HERE))
    import server
    client = TestClient(server.app, base_url=B)   # the daemon only answers to its own host


def request(path, body=None, headers=None):
    """Returns (status, json) for any request, including refused ones."""
    method = "GET" if body is None else "POST"
    headers = {"Content-Type": "application/json", **(headers or {})}
    if client is not None:
        r = client.request(method, path, headers=headers, content=None if body is None else json.dumps(body))
        return r.status_code, r.json()
    req = urllib.request.Request(B + path, data=None if body is None else json.dumps(body).encode(),
                                 headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def call(path, body=None):
    return request(path, body)[1]


def device(call_app=None, remote=(), caller=None, private=False):
    call("/device/context", {"call_app": call_app, "caller": caller, "remote_access": list(remote), "private_window": private})


def wire(amount=8500, new_payee=True, account="987654321012", **extra):
    return call("/evaluate/action", {"origin": "chase.com", "action_type": "wire_transfer", "amount": amount,
                                     "new_payee": new_payee, "routing_number": "021000021", "account_number": account, **extra})


def heard(text, chunk=0):
    return call("/calls/transcript", {"chunk": chunk, "text": text})["heard"]


ok = lambda name, cond, extra="": print(("PASS " if cond else "FAIL ") + name, extra) or cond
results, skipped = [], []
start_server()

try:
    # 1) the moment: device signals
    call("/reset", {})
    r = wire()
    results.append(ok("nothing unusual: the payment goes through", r["decision"] == "ALLOW"))
    device("FaceTime", ["AnyDesk"])
    r = wire(new_payee=False)
    results.append(ok("call + remote control intercepts even to an existing payee", r["decision"] == "INTERCEPT", r["score"]))
    device(None, ["AnyDesk"])
    r = wire()
    status, _ = request("/override", {"action_id": r["action_id"]})
    results.append(ok("'Send anyway' is locked while remote control runs, even at medium risk",
                      r["decision"] == "CHALLENGE" and r["locked"] and status == 409, f'{r["decision"]} {status}'))
    call("/reset", {})
    device("FaceTime", private=True)
    since = time.time()
    r = wire()
    alerts = call(f"/device/alerts?after={since}")
    results.append(ok("during a call, even a medium-risk alert goes to the private window",
                      r["decision"] == "CHALLENGE" and r["private_overlay"] and r["decoy"] and len(alerts) == 1))
    results.append(ok("the alert cursor is a timestamp (no lost alerts after a restart)",
                      call(f"/device/alerts?after={alerts[0]['ts']}") == []))

    # 2) "Send anyway" for a high-risk payment
    call("/reset", {})
    device("FaceTime", ["AnyDesk"])
    paused = wire()
    status, _ = request("/override", {"action_id": paused["action_id"]})
    results.append(ok("'Send anyway' waits while the call is live", status == 409, status))
    device()
    tok = call("/override", {"action_id": paused["action_id"]})["override_token"]
    results.append(ok("the release doesn't fit a different payment", wire(amount=900, override_token=tok)["decision"] != "ALLOW"))
    results.append(ok("the release works once, for that payment", wire(override_token=tok)["decision"] == "ALLOW"))
    results.append(ok("…and only once", wire(override_token=tok)["path"] != "override"))
    status, _ = request("/override", {"action_id": "act_unknown"})
    results.append(ok("unknown payment: 404", status == 404, status))

    # 3) the journal: calls and what was heard
    call("/reset", {})
    device("FaceTime", caller="Daniel")
    h = heard("Buy five hundred dollars in Target gift cards and read me the numbers.")
    h2 = heard("Buy five hundred dollars in Target gift cards and read me the numbers.")   # same chunk again
    results.append(ok("hearing 'gift cards' on a call is recorded once per chunk",
                      [x["label"] for x in h].count("gift_cards") == 1 and h2 == []))
    alerts = call("/device/alerts?after=0")
    results.append(ok("…and raises a live alert about gift cards", alerts and "gift cards" in alerts[0]["title"]))
    h = heard("Now read me the code you just got, it's 482913.", chunk=1)
    results.append(ok("snippets drop long numbers such as codes",
                      any(x["label"] == "one_time_code" and "482913" not in x["snippet"] for x in h), h))
    calls = call("/state")["track"]["recent_calls"]
    results.append(ok("the call is in the journal, live, with the caller's name",
                      calls and calls[0]["live"] and calls[0]["who"] == "Daniel"))
    device()
    calls = call("/state")["track"]["recent_calls"]
    results.append(ok("the call closes when it ends", not calls[0]["live"]))

    # 4) the long-term track: a 3-week romance scam
    call("/demo/seed", {})
    people = {c["name"]: c for c in call("/state")["track"]["contacts"]}
    d = people.get("Daniel", {})
    results.append(ok("Daniel's three weeks read as an escalating money pattern",
                      d.get("stage") == 5 and d.get("risk") == "high", d.get("stage_name")))
    results.append(ok("…with plain-words flags", any("Known for only" in f for f in d.get("flags", []))
                      and any("keep things from your family" in f for f in d.get("flags", []))))
    results.append(ok("the daughter's weekly calls stay low risk", people.get("Sarah (daughter)", {}).get("risk") == "low"))
    r = wire()
    results.append(ok("the history alone pauses a new-payee wire, naming Daniel",
                      r["decision"] == "INTERCEPT" and "long_term_pattern" in r["components"]
                      and any("Daniel" in x for x in r["reasons"]), r["components"]))
    device("FaceTime", caller="Daniel")
    heard("The hospital needs the money today. Please send eight thousand five hundred dollars.", chunk=5)
    r = wire()
    results.append(ok("during his call, after he asks again: 100 and locked",
                      r["score"] == 100 and r["locked"] and "money_asked_on_call" in r["components"], r["reasons"]))
    device()
    call("/reset", {})
    results.append(ok("Reset clears the journal", call("/state")["track"]["contacts"] == []))

    # 5) only the page itself may call the daemon
    status, _ = request("/reset", {}, headers={"Origin": "https://evil.example"})
    results.append(ok("a web page cannot call the daemon", status == 403, status))
    status, _ = request("/state", headers={"Host": "evil.example:8777"})
    results.append(ok("DNS-rebinding host is refused", status == 403, status))

    # 6) the browser
    browser_checks = ["browser: with someone watching and the private window, the page shows only the stall",
                      "browser: 'Send anyway' waits for the call to end, then sends once",
                      "browser: the form never submits natively (no navigation)",
                      "browser: the 3-week story shows Daniel's card and the call journal"]
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        sync_playwright = None
    if not srv or sync_playwright is None:
        skipped += browser_checks
    else:
        alert_js = "document.getElementById('es-alert').shadowRoot.getElementById('anyway')"
        with sync_playwright() as pw:
            page = pw.chromium.launch().new_page(viewport={"width": 1280, "height": 900})
            call("/reset", {})
            device("FaceTime", ["AnyDesk"], private=True)
            page.goto(B)
            page.click("button[type=submit]")
            page.wait_for_selector("#decoy", state="visible")
            results.append(ok(browser_checks[0], page.evaluate("!document.getElementById('es-alert')")))

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
            results.append(ok(browser_checks[1], locked))
            results.append(ok(browser_checks[2], page.url.rstrip("/") == B))

            call("/reset", {})
            page.goto(B)
            page.click("text=Load 3-week story")
            page.wait_for_selector(".person.high")
            page.wait_for_timeout(400)
            text = page.inner_text("aside")
            page.screenshot(path=str(HERE / "demo_intercept.png"), full_page=True)
            results.append(ok(browser_checks[3], "Daniel" in text and "escalating" in text and "hospital" in text.lower()))
            call("/reset", {})
finally:
    if srv:
        srv.terminate()

for name in skipped:
    print("SKIP " + name)
print(f"\n{sum(results)}/{len(results)} passed" + (f", {len(skipped)} skipped" if skipped else ""))
sys.exit(0 if all(results) else 1)
