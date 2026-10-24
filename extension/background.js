// Relays checks from the Gmail tab to the ElderShield daemon on this computer. Content scripts
// can't call localhost themselves (the page's CORS rules apply to them); the extension can.
chrome.runtime.onMessage.addListener(({trigger}, _sender, reply) => {
  fetch('http://127.0.0.1:8777/ingest/trigger', {
    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(trigger),
  })
    .then(r => r.ok ? r.json() : Promise.reject(r.status))
    .then(reply, () => reply({error: 'ElderShield is not running'}));
  return true;   // reply asynchronously
});
