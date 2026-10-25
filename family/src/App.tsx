import { useState } from 'react';
import { useSpacetimeDB, useTable, useReducer } from 'spacetimedb/react';
import { tables, reducers } from './module_bindings';

const now = () => Date.now() / 1000;

function ago(ts: number): string {
  const s = Math.max(0, now() - ts);
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return new Date(ts * 1000).toLocaleDateString([], { weekday: 'short', month: 'short', day: 'numeric' });
}

export default function App() {
  const { isActive, connectionError } = useSpacetimeDB();
  const [memberships, membersReady] = useTable(tables.myMemberships);
  const [households] = useTable(tables.myHouseholds);
  const [alerts] = useTable(tables.myAlerts);

  if (connectionError) return <Shell><p className="err">Can't reach ElderShield's database: {String(connectionError)}</p></Shell>;
  if (!isActive || !membersReady) return <Shell><p className="muted">Connecting…</p></Shell>;
  if (memberships.length === 0) return <Shell><Join /></Shell>;

  const me = memberships[0];
  const home = households.find(h => h.id === me.householdId);
  const elder = home?.elderName ?? 'her';
  const sorted = [...alerts].sort((a, b) => b.ts - a.ts);

  return (
    <Shell>
      <p className="who">You're in <b>{elder}</b>'s circle as <b>{me.name}</b>{me.relation ? ` (${me.relation})` : ''}.</p>
      <p className="muted small">
        {home?.shareLevel === 'warnings'
          ? `${elder} shares both paused payments and warnings heard on her calls with you.`
          : `${elder} shares paused payments with you. Warnings during calls stay with her.`}
        {' '}She can change that, or remove you, at any time. You never see her calls or her bank.
      </p>
      {sorted.length === 0
        ? <div className="empty"><b>All quiet.</b> If ElderShield ever pauses a payment for {elder}, it shows up here the same second, and one press tells her you're calling.</div>
        : sorted.map(a => <Alert key={String(a.id)} a={a} me={me.name} elder={elder} />)}
    </Shell>
  );
}

function Alert({ a, me, elder }: { a: { id: bigint; ts: number; kind: string; title: string; body: string; acknowledgedBy: string; acknowledgedAt: number }; me: string; elder: string }) {
  const acknowledge = useReducer(reducers.acknowledgeAlert);
  const [busy, setBusy] = useState(false);
  const fresh = now() - a.ts < 3600;
  return (
    <div className={`alert ${a.kind} ${fresh && !a.acknowledgedBy ? 'fresh' : ''}`}>
      <div className="head">
        <span className={`kind ${a.kind}`}>{a.kind === 'payment' ? 'payment paused' : 'heard on a call'}</span>
        <span className="muted">{ago(a.ts)}</span>
      </div>
      <h2>{a.title}</h2>
      <p>{a.body}</p>
      {a.acknowledgedBy
        ? <div className="ack">✓ {a.acknowledgedBy === me ? 'You' : a.acknowledgedBy} said {a.acknowledgedBy === me ? "you're" : "they're"} calling {elder} · {ago(a.acknowledgedAt)}</div>
        : <button disabled={busy} onClick={async () => { setBusy(true); try { await acknowledge({ id: a.id, now: now() }); } finally { setBusy(false); } }}>
            I've seen this — I'm calling {elder}
          </button>}
    </div>
  );
}

function Join() {
  const join = useReducer(reducers.joinHousehold);
  const [code, setCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  return (
    <form className="join" onSubmit={async e => {
      e.preventDefault(); setBusy(true); setError(null);
      try { await join({ inviteCode: code, now: now() }); }
      catch (err) { setError(err instanceof Error ? err.message : String(err)); }
      finally { setBusy(false); }
    }}>
      <h2>Enter the code she gave you</h2>
      <p className="muted small">Only she can add you. The six-letter code comes from her ElderShield page; she decides who is in her circle and how much they hear.</p>
      <input value={code} onChange={e => setCode(e.target.value.toUpperCase())} placeholder="e.g. B887FX" maxLength={6} autoFocus spellCheck={false} />
      <button disabled={busy || code.trim().length < 6}>Join her circle</button>
      {error && <p className="err">{error}</p>}
    </form>
  );
}

function Shell({ children }: { children: React.ReactNode }) {
  return (
    <main>
      <header><span className="dot" /><b>ElderShield</b><span className="muted"> · her circle</span></header>
      {children}
      <footer className="muted small">Live from her ElderShield, through SpacetimeDB. Alerts are hers to share; this page only ever shows what she chose.</footer>
    </main>
  );
}
