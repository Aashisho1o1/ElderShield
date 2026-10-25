// ElderShield's memory, living inside SpacetimeDB.
//
// The journal of her calls (who, when, how long, which warning signs were heard), the payments
// ElderShield paused, Jev's judgments, and her circle: the people she has chosen to tell when
// something is wrong. The daemon on her Mac (server.py) writes through the reducers below; the
// family page subscribes to the views at the bottom and sees only what she has decided to share.
//
// Times are Unix seconds (f64), as the daemon keeps them. Columns are snake_case so the daemon's
// SQL and the rows it reads back look the same as they always did.
import { schema, table, t, SenderError, type InferSchema, type ReducerCtx } from 'spacetimedb/server';

// --- the journal -----------------------------------------------------------------------------

const config = table({ name: 'config' }, {
  id: t.u32().primaryKey(),
  owner: t.identity(),              // whoever published the module: the only writer of the journal
});

const contact = table({ name: 'contact' }, {
  id: t.string().primaryKey(),      // salted hash of the caller's name/number; "unknown" otherwise
  label: t.string(),
  first_seen: t.f64(),
});

const callLog = table({ name: 'call_log' }, {
  id: t.string().primaryKey(),
  contact_id: t.string().index('btree'),
  app: t.string(),
  started: t.f64(),
  ended: t.f64(),                   // 0 while the call is live
  live: t.bool(),
  remote_access: t.string(),        // JSON list of remote-control apps seen during the call
});

const signal = table({ name: 'signal' }, {
  key: t.string().primaryKey(),     // "<call>:<chunk>:<label>:<source>", so a partial can be updated
  call_id: t.string().index('btree'),
  contact_id: t.string().index('btree'),
  ts: t.f64(),
  label: t.string(),
  confidence: t.f64(),
  snippet: t.string(),              // the flagged sentence, numbers removed; "" when snippets are off
  source: t.string(),               // "rules" or "jev"
});

const remoteAccessSeen = table({ name: 'remote_access_seen' }, {
  name: t.string().primaryKey(),
  last_seen: t.f64(),
});

const payment = table({ name: 'payment' }, {
  action_id: t.string().primaryKey(),
  ts: t.f64(),
  fingerprint: t.string(),
  action_type: t.string(),
  amount: t.f64(),                  // -1 when unknown
  decision: t.string(),
  score: t.i32(),
  call_id: t.string(),              // "" when no call was live
  released_by: t.string(),          // "senior" when she pressed Send anyway; "" otherwise
});

const assessment = table({ name: 'assessment' }, {
  id: t.u64().primaryKey().autoInc(),
  ts: t.f64(),
  contact_id: t.string().index('btree'),
  call_id: t.string(),
  fraud_likely: t.f64(),
  financial_steering: t.f64(),
  isolation: t.f64(),
  escalation: t.f64(),
  pattern: t.string(),
  pattern_confidence: t.f64(),
  evidence: t.string(),             // JSON: the counts and labels Jev was shown, never words
  model: t.string(),
  ms: t.i32(),
});

const release = table({ name: 'release' }, {
  token: t.string().primaryKey(),   // a "Send anyway" release: one payment, one use, 15 minutes
  action_id: t.string(),
  fingerprint: t.string(),
  decision: t.string(),
  created_at: t.f64(),
  expires_at: t.f64(),
  used_at: t.f64(),                 // 0 until used
});

// --- her circle ------------------------------------------------------------------------------
// She decides who is in it, and how much they hear. Nobody can add themselves; a person joins
// only with a code she hands them, and she can remove anyone at any time, which also takes every
// alert back out of their view.

const household = table({ name: 'household' }, {
  id: t.u64().primaryKey().autoInc(),
  elder_name: t.string(),
  share_level: t.string(),          // "payments": only paused payments; "warnings": also live-call warnings
  created_at: t.f64(),
});

const trustedPerson = table({ name: 'trusted_person' }, {
  id: t.u64().primaryKey().autoInc(),
  household_id: t.u64().index('btree'),
  name: t.string(),
  relation: t.string(),
  invite_code: t.string().unique(),
  identity: t.option(t.identity()), // set when they join with the code
  joined_at: t.f64(),
  added_at: t.f64(),
});

const familyAlert = table({ name: 'family_alert' }, {
  id: t.u64().primaryKey().autoInc(),
  household_id: t.u64().index('btree'),
  ts: t.f64(),
  kind: t.string(),                 // "payment" (a paused payment) or "warning" (heard on a call)
  title: t.string(),
  body: t.string(),
  acknowledged_by: t.string(),      // the trusted person's name, once one presses "I'm calling her"
  acknowledged_at: t.f64(),
});

const spacetimedb = schema({
  config, contact, callLog, signal, remoteAccessSeen, payment, assessment, release,
  household, trustedPerson, familyAlert,
});
export default spacetimedb;

type Ctx = ReducerCtx<InferSchema<typeof spacetimedb>>;

export const init = spacetimedb.init(ctx => {
  ctx.db.config.insert({ id: 0, owner: ctx.sender });
});

/** Only the daemon that published this module writes the journal. */
function daemonOnly(ctx: Ctx): void {
  const cfg = ctx.db.config.id.find(0);
  if (!cfg || !cfg.owner.equals(ctx.sender)) throw new SenderError('only ElderShield on her computer may write the journal');
}

function theHousehold(ctx: Ctx) {
  const rows = [...ctx.db.household.iter()];
  return rows.length ? rows[0] : null;
}

/** The trusted-person row for whoever is calling, if she has let them in. */
function membership(ctx: Ctx) {
  return [...ctx.db.trustedPerson.iter()].filter(p => p.identity && p.identity.equals(ctx.sender));
}

// --- reducers the daemon calls ----------------------------------------------------------------

export const upsertContact = spacetimedb.reducer(
  { id: t.string(), label: t.string(), first_seen: t.f64() },
  (ctx, { id, label, first_seen }) => {
    daemonOnly(ctx);
    if (!ctx.db.contact.id.find(id)) ctx.db.contact.insert({ id, label, first_seen });
  });

export const startCall = spacetimedb.reducer(
  { id: t.string(), contact_id: t.string(), app: t.string(), started: t.f64(), remote_access: t.string() },
  (ctx, a) => {
    daemonOnly(ctx);
    ctx.db.callLog.insert({ ...a, ended: 0, live: true });
  });

export const endCall = spacetimedb.reducer(
  { id: t.string(), ended: t.f64() },
  (ctx, { id, ended }) => {
    daemonOnly(ctx);
    const c = ctx.db.callLog.id.find(id);
    if (c) ctx.db.callLog.id.update({ ...c, ended, live: false });
  });

export const setCallRemoteAccess = spacetimedb.reducer(
  { id: t.string(), remote_access: t.string() },
  (ctx, { id, remote_access }) => {
    daemonOnly(ctx);
    const c = ctx.db.callLog.id.find(id);
    if (c) ctx.db.callLog.id.update({ ...c, remote_access });
  });

export const noteRemoteAccess = spacetimedb.reducer(
  { name: t.string(), last_seen: t.f64() },
  (ctx, { name, last_seen }) => {
    daemonOnly(ctx);
    const r = ctx.db.remoteAccessSeen.name.find(name);
    if (r) ctx.db.remoteAccessSeen.name.update({ ...r, last_seen });
    else ctx.db.remoteAccessSeen.insert({ name, last_seen });
  });

export const addSignal = spacetimedb.reducer(
  { key: t.string(), call_id: t.string(), contact_id: t.string(), ts: t.f64(), label: t.string(),
    confidence: t.f64(), snippet: t.string(), source: t.string() },
  (ctx, a) => {
    daemonOnly(ctx);
    const s = ctx.db.signal.key.find(a.key);
    if (s) ctx.db.signal.key.update({ ...s, snippet: a.snippet });   // the same chunk again, more of the sentence
    else ctx.db.signal.insert(a);
  });

export const recordPayment = spacetimedb.reducer(
  { action_id: t.string(), ts: t.f64(), fingerprint: t.string(), action_type: t.string(), amount: t.f64(),
    decision: t.string(), score: t.i32(), call_id: t.string(), released_by: t.string() },
  (ctx, a) => {
    daemonOnly(ctx);
    ctx.db.payment.insert(a);
  });

export const addRelease = spacetimedb.reducer(
  { token: t.string(), action_id: t.string(), fingerprint: t.string(), decision: t.string(),
    created_at: t.f64(), expires_at: t.f64() },
  (ctx, a) => {
    daemonOnly(ctx);
    ctx.db.release.insert({ ...a, used_at: 0 });
  });

/** Single use, bound to one exact payment, and only within its window; fails otherwise. */
export const takeRelease = spacetimedb.reducer(
  { token: t.string(), fingerprint: t.string(), now: t.f64() },
  (ctx, { token, fingerprint, now }) => {
    daemonOnly(ctx);
    const r = ctx.db.release.token.find(token);
    if (!r || r.fingerprint !== fingerprint || r.used_at !== 0 || r.expires_at <= now) {
      throw new SenderError('no usable release for this payment');
    }
    ctx.db.release.token.update({ ...r, used_at: now });
  });

export const addAssessment = spacetimedb.reducer(
  { ts: t.f64(), contact_id: t.string(), call_id: t.string(), fraud_likely: t.f64(), financial_steering: t.f64(),
    isolation: t.f64(), escalation: t.f64(), pattern: t.string(), pattern_confidence: t.f64(),
    evidence: t.string(), model: t.string(), ms: t.i32() },
  (ctx, a) => {
    daemonOnly(ctx);
    ctx.db.assessment.insert({ id: 0n, ...a });
  });

/** Forget everything about calls and payments. Her circle stays: that is her decision, not data. */
export const clearJournal = spacetimedb.reducer(ctx => {
  daemonOnly(ctx);
  for (const r of [...ctx.db.contact.iter()]) ctx.db.contact.id.delete(r.id);
  for (const r of [...ctx.db.callLog.iter()]) ctx.db.callLog.id.delete(r.id);
  for (const r of [...ctx.db.signal.iter()]) ctx.db.signal.key.delete(r.key);
  for (const r of [...ctx.db.remoteAccessSeen.iter()]) ctx.db.remoteAccessSeen.name.delete(r.name);
  for (const r of [...ctx.db.payment.iter()]) ctx.db.payment.action_id.delete(r.action_id);
  for (const r of [...ctx.db.assessment.iter()]) ctx.db.assessment.id.delete(r.id);
  for (const r of [...ctx.db.release.iter()]) ctx.db.release.token.delete(r.token);
  for (const r of [...ctx.db.familyAlert.iter()]) ctx.db.familyAlert.id.delete(r.id);
});

// --- her circle: what she decides ------------------------------------------------------------

export const ensureHousehold = spacetimedb.reducer(
  { elder_name: t.string(), now: t.f64() },
  (ctx, { elder_name, now }) => {
    daemonOnly(ctx);
    const h = theHousehold(ctx);
    if (!h) ctx.db.household.insert({ id: 0n, elder_name, share_level: 'payments', created_at: now });
    else if (h.elder_name !== elder_name) ctx.db.household.id.update({ ...h, elder_name });
  });

export const setShareLevel = spacetimedb.reducer(
  { share_level: t.string() },
  (ctx, { share_level }) => {
    daemonOnly(ctx);
    if (share_level !== 'payments' && share_level !== 'warnings') throw new SenderError('unknown share level');
    const h = theHousehold(ctx);
    if (h) ctx.db.household.id.update({ ...h, share_level });
  });

/** She adds someone by name; the code is what she hands them, in person or by text. */
export const addTrustedPerson = spacetimedb.reducer(
  { name: t.string(), relation: t.string(), now: t.f64() },
  (ctx, { name, relation, now }) => {
    daemonOnly(ctx);
    const h = theHousehold(ctx);
    if (!h) throw new SenderError('no household yet');
    const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';     // no 0/O or 1/I to misread over the phone
    let code = '';
    for (let i = 0; i < 6; i++) code += alphabet[ctx.random.integerInRange(0, alphabet.length - 1)];
    ctx.db.trustedPerson.insert({ id: 0n, household_id: h.id, name, relation, invite_code: code,
                                  identity: undefined, joined_at: 0, added_at: now });
  });

export const removeTrustedPerson = spacetimedb.reducer(
  { id: t.u64() },
  (ctx, { id }) => {
    daemonOnly(ctx);
    ctx.db.trustedPerson.id.delete(id);
  });

/** A family member joins with the code she gave them. Their identity is then the key to her alerts. */
export const joinHousehold = spacetimedb.reducer(
  { invite_code: t.string(), now: t.f64() },
  (ctx, { invite_code, now }) => {
    const p = ctx.db.trustedPerson.invite_code.find(invite_code.trim().toUpperCase());
    if (!p) throw new SenderError('That code is not one she has given out.');
    if (p.identity && !p.identity.equals(ctx.sender)) throw new SenderError('That code has already been used.');
    ctx.db.trustedPerson.id.update({ ...p, identity: ctx.sender, joined_at: p.joined_at || now });
  });

export const postFamilyAlert = spacetimedb.reducer(
  { kind: t.string(), title: t.string(), body: t.string(), ts: t.f64() },
  (ctx, a) => {
    daemonOnly(ctx);
    const h = theHousehold(ctx);
    if (!h) return;
    ctx.db.familyAlert.insert({ id: 0n, household_id: h.id, ...a, acknowledged_by: '', acknowledged_at: 0 });
  });

/** "I've seen this, I'm calling her": one press, and she sees who is on the way. */
export const acknowledgeAlert = spacetimedb.reducer(
  { id: t.u64(), now: t.f64() },
  (ctx, { id, now }) => {
    const a = ctx.db.familyAlert.id.find(id);
    if (!a) throw new SenderError('no such alert');
    const me = membership(ctx).find(p => p.household_id === a.household_id);
    if (!me) throw new SenderError('you are not in her circle');
    if (a.acknowledged_by) return;
    ctx.db.familyAlert.id.update({ ...a, acknowledged_by: me.name, acknowledged_at: now });
  });

// --- what a family member can see: their own membership, her name, and the alerts she shares ---

// (A view's context is read-only, so the membership check is spelled out again here.)
export const myMemberships = spacetimedb.view(
  { name: 'my_memberships', public: true },
  t.array(trustedPerson.rowType),
  ctx => [...ctx.db.trustedPerson.iter()].filter(p => p.identity && p.identity.equals(ctx.sender)));

export const myHouseholds = spacetimedb.view(
  { name: 'my_households', public: true },
  t.array(household.rowType),
  ctx => {
    const mine = [...ctx.db.trustedPerson.iter()].filter(p => p.identity && p.identity.equals(ctx.sender));
    const ids = new Set(mine.map(p => p.household_id));
    return [...ctx.db.household.iter()].filter(h => ids.has(h.id));
  });

export const myAlerts = spacetimedb.view(
  { name: 'my_alerts', public: true },
  t.array(familyAlert.rowType),
  ctx => {
    const out = [];
    const mine = [...ctx.db.trustedPerson.iter()].filter(p => p.identity && p.identity.equals(ctx.sender));
    for (const p of mine) {
      const h = ctx.db.household.id.find(p.household_id);
      if (!h) continue;
      for (const a of ctx.db.familyAlert.household_id.filter(p.household_id)) {
        if (a.kind === 'payment' || h.share_level === 'warnings') out.push(a);
      }
    }
    return out;
  });
