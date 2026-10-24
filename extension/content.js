// ElderShield for Gmail: when a message is opened, check it with the ElderShield daemon and show
// the verdict right above it. Only messages the user opens are read, and they go only to this
// computer. Gmail's class names (a3s body, gD sender, hP subject) are long-standing but unofficial.
const MAX_CHARS = 20000;

function scan() {
  for (const body of document.querySelectorAll('div.a3s')) {
    if (body.dataset.esChecked) continue;
    body.dataset.esChecked = '1';
    check(body);
  }
}
new MutationObserver(scan).observe(document.body, {childList: true, subtree: true});
scan();

async function check(body) {
  const msg = body.closest('[data-message-id]');
  const id = msg && 'es:' + msg.getAttribute('data-message-id');
  // Re-opening a message reuses its verdict, so it isn't counted as a fresh message each time.
  let verdict = id && (await chrome.storage.local.get(id))[id];
  if (!verdict) {
    verdict = await ask(body, msg);
    if (id && !verdict.offline) chrome.storage.local.set({[id]: verdict});
  }
  show(body, verdict);
}

async function ask(body, msg) {
  const hosts = [...new Set([...body.querySelectorAll('a[href^="http"]')].map(a => new URL(a.href).hostname))];
  const subject = document.querySelector('h2.hP')?.textContent || '';
  const trigger = {
    tab_id: 'gmail', channel: 'email', has_voice_session: false,
    sender: msg?.querySelector('span.gD[email]')?.getAttribute('email') || 'unknown-sender',
    // HTML, so the daemon's hidden-text stripper can see inline styles.
    content: `Subject: ${subject}\n${body.innerHTML}`.slice(0, MAX_CHARS) + (hosts.length ? `\nLinks: ${hosts.join(' ')}` : ''),
  };
  const res = await chrome.runtime.sendMessage({trigger});
  if (!res || res.error) return {offline: true};
  const links = disguisedLinks(body);
  return {scam: res.is_threat || links.length > 0, reasons: [...res.explanation, ...links]};
}

// A link whose text is one web address but which goes somewhere else: the classic phishing tell.
function disguisedLinks(body) {
  const out = [];
  for (const a of body.querySelectorAll('a[href^="http"]')) {
    const m = a.textContent.trim().match(/^(?:https?:\/\/)?(?:www\.)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:\/\S*)?$/i);
    const real = new URL(a.href).hostname.replace(/^www\./, '');
    if (m && real !== m[1].toLowerCase() && !real.endsWith('.' + m[1].toLowerCase()))
      out.push(`a link that says ${m[1]} but really goes to ${real}`);
  }
  return out;
}

const esc = s => String(s).replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));

function show(body, v) {
  const host = document.createElement('div');
  host.className = 'es-verdict';
  body.before(host);
  // Shadow DOM: Gmail's styles can't reach in, and the email's own HTML can't restyle or hide it.
  host.attachShadow({mode: 'open'}).innerHTML = `
    <style>
      :host{all:initial;display:block;margin:4px 0 14px}
      .card{font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;color:#edeef2;
        background:hsl(252,10%,10%);border-radius:16px;padding:16px 18px;max-width:640px;
        box-shadow:0 0 0 1px rgba(207,226,255,.24),0 8px 24px rgba(0,0,0,.18)}
      .h{display:flex;align-items:center;gap:8px;font-size:13px;color:#898b91;margin-bottom:6px}
      .led{width:7px;height:7px;border-radius:50%;background:#f87171}
      .t{font-size:20px;font-weight:600;margin-bottom:6px}
      ul{margin:6px 0 10px;padding-left:20px}
      .s{font-size:15px;color:#b2b3ba}
      .pill{display:inline-flex;align-items:center;gap:8px;font:13px/1 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
        color:#5f6368;background:#f1f3f4;border-radius:999px;padding:6px 12px}
      .pill .led{background:${v.offline ? '#9aa0a6' : '#34a853'}}
    </style>
    ${v.scam ? `
      <div class="card" role="alert">
        <div class="h"><span class="led"></span>ElderShield</div>
        <div class="t">This email has signs of a scam</div>
        <div>It shows:</div>
        <ul>${v.reasons.map(r => `<li>${esc(r)}</li>`).join('')}</ul>
        <div class="s">Don't reply, click its links, or call numbers in it. To check, call your bank
          using the number on the back of your card.</div>
      </div>`
    : `<span class="pill"><span class="led"></span>${v.offline
        ? 'ElderShield is off, so this email was not checked'
        : 'ElderShield found no warning signs'}</span>`}`;
}
