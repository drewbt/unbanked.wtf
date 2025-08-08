// Unbanked — robust Generate Link: better input validation, clearer errors, audit logs
// Features: recipient-locked claims, mint-on-claim, single Authenticate, KV-backed history

const kv = await Deno.openKv();
const INDEX_HTML = await Deno.readTextFile(new URL("./index.html", import.meta.url));

type User = { userId: string; handle: string; secretHash: string; createdAt: number; };
type Pending = {
  claimId: string; fromUserId: string; toHandle: string; amount: number; currency: string; note: string;
  createdAt: number; claimedAt?: number; claimedBy?: string;
};
type Txn = {
  id: string; userId: string; userHandle: string; kind: "credit" | "debit";
  amount: number; currency: string; note: string; counterpartyHandle: string; ts: number;
};

// KV keys
const kUserByHandleLower = (h: string) => ["userByHandle", h.toLowerCase()] as const;
const kUserByHandleRaw   = (h: string) => ["userByHandle", h] as const; // legacy index (pre-lowercasing)
const kUser = (id: string) => ["user", id] as const;
const kApiKey = (apiKey: string) => ["apiKey", apiKey] as const;
const kPending = (claimId: string) => ["pending", claimId] as const;
const kBalance = (userId: string, cur: string) => ["balance", userId, cur] as const;
const kTxPrefix = (userId: string) => ["tx", userId] as const;
const kTx = (userId: string, ts: number, id: string) => ["tx", userId, ts, id] as const;

// utils
const enc = new TextEncoder();
function nowSec(){ return Math.floor(Date.now()/1000); }
function uuid(){ return crypto.randomUUID(); }
async function sha256(s: string){ const d=await crypto.subtle.digest("SHA-256", enc.encode(s)); return [...new Uint8Array(d)].map(b=>b.toString(16).padStart(2,"0")).join(""); }
function json(status: number, body: unknown, headers: HeadersInit = {}){ return new Response(JSON.stringify(body), { status, headers: { "content-type":"application/json; charset=utf-8", ...headers } }); }
function bad(msg: string, status=400){ return json(status, { error: msg }); }
function audit(event: string, data: Record<string, unknown> = {}){ console.log(JSON.stringify({ ts: nowSec(), evt: event, ...data })); }

// lookups (with legacy backfill)
async function getUserByHandle(handle: string): Promise<User|null> {
  const lc = handle.toLowerCase();
  let id = await kv.get<string>(kUserByHandleLower(lc));
  if (!id.value) {
    const legacy = await kv.get<string>(kUserByHandleRaw(handle));
    if (legacy.value) {
      await kv.set(kUserByHandleLower(lc), legacy.value);
      audit("index.backfill", { handle, to: lc, userId: legacy.value });
      id = legacy;
    }
  }
  if (!id.value) return null;
  const u = await kv.get<User>(kUser(id.value));
  return u.value ?? null;
}
async function getUserById(userId: string){ const u=await kv.get<User>(kUser(userId)); return u.value ?? null; }
async function getUserByApiKey(apiKey: string){ const uid=await kv.get<string>(kApiKey(apiKey)); if(!uid.value) return null; return await getUserById(uid.value); }
async function authUser(req: Request){ const a=req.headers.get("authorization")||""; const token=a.startsWith("Bearer ")? a.slice(7):""; return token? getUserByApiKey(token): null; }

// KV helpers
async function creditBalance(userId: string, cur: string, amount: number){
  const key = kBalance(userId, cur);
  for (let i=0;i<12;i++){
    const curVal = await kv.get<number>(key);
    const ver = curVal.versionstamp; // null OK
    const next = (curVal.value ?? 0) + amount;
    const res = await kv.atomic().check({ key, versionstamp: ver }).set(key, next).commit();
    if (res.ok) return next;
  }
  throw new Error("balance contention");
}
async function recordTx(t: Txn){
  await kv.set(kTx(t.userId, t.ts, t.id), t);
  audit("tx.recorded", { userId:t.userId, userHandle:t.userHandle, kind:t.kind, amount:t.amount, currency:t.currency, note:t.note, counterparty:t.counterpartyHandle, txId:t.id, ts:t.ts });
}

// server
Deno.serve(async (req) => {
  const url = new URL(req.url);
  const { pathname } = url;

  // static
  if (req.method === "GET" && (pathname === "/" || pathname === "/index.html")) {
    return new Response(INDEX_HTML, { headers: { "content-type":"text/html; charset=utf-8" } });
  }

  // CORS
  if (req.method === "OPTIONS") {
    return new Response("", { headers: {
      "access-control-allow-origin":"*",
      "access-control-allow-methods":"GET,POST,OPTIONS",
      "access-control-allow-headers":"content-type,authorization",
    }});
  }

  // authenticate (login-or-create)
  if (pathname === "/api/authenticate" && req.method === "POST") {
    const b = await req.json().catch(()=> ({}));
    const handle = String(b.handle||"").trim();
    const secret = String(b.secret||"");
    const accepted = !!b.acceptedDisclaimer;
    if (!handle || !secret) return bad("handle and secret required");
    if (!/^[a-z0-9_.-]{3,32}$/i.test(handle)) return bad("invalid handle");

    const existing = await getUserByHandle(handle);
    if (existing){
      const ok = (await sha256(secret)) === existing.secretHash;
      if (!ok){ audit("auth.fail", { handle }); return bad("invalid credentials", 401); }
      const apiKey = uuid(); await kv.set(kApiKey(apiKey), existing.userId);
      audit("auth.login", { userId: existing.userId, handle: existing.handle });
      return json(200, { userId: existing.userId, apiKey, handle: existing.handle });
    } else {
      if (!accepted) return bad("accept disclaimer to create account");
      const userId = uuid();
      const user: User = { userId, handle, secretHash: await sha256(secret), createdAt: nowSec() };
      const apiKey = uuid();
      const ok = await kv.atomic()
        .check({ key: kUserByHandleLower(handle), versionstamp: null })
        .set(kUserByHandleLower(handle), userId)
        .set(kUser(userId), user)
        .set(kApiKey(apiKey), userId)
        .commit();
      if (!ok.ok) return bad("handle already taken", 409);
      audit("auth.signup", { userId, handle });
      return json(200, { userId, apiKey, handle });
    }
  }

  // create recipient-locked link (now resilient)
  if (pathname === "/api/link" && req.method === "POST") {
    const me = await authUser(req);
    if (!me) { audit("link.err.unauth", {}); return bad("unauthorized", 401); }
    const b = await req.json().catch(()=> ({}));

    // sanitize handle
    let to = String(b.toHandle||"").trim();
    if (to.startsWith("@")) to = to.slice(1);
    // sanitize amount (also accept "12,5")
    const rawAmt = String(b.amount ?? "").replace(/\s+/g,"").replace(",",".");
    const amount = Number(rawAmt);
    const currency = String(b.currency||"").trim().toUpperCase();
    const note = String(b.note||"").trim();

    if (!/^[a-z0-9_.-]{3,32}$/i.test(to)) { audit("link.err.badTo",{to}); return bad("valid toHandle required (letters, numbers, _ . -)"); }
    if (!isFinite(amount) || amount<=0) { audit("link.err.badAmount",{rawAmt}); return bad("amount must be > 0"); }
    if (!/^[A-Z0-9]{2,6}$/.test(currency)) { audit("link.err.badCur",{currency}); return bad("invalid currency code"); }

    const claimId = uuid();
    const p: Pending = { claimId, fromUserId: me.userId, toHandle: to.toLowerCase(), amount:+amount.toFixed(8), currency, note, createdAt: nowSec() };
    await kv.set(kPending(claimId), p);

    // sender history (no debit)
    const ts = nowSec();
    await recordTx({ id:`send:${claimId}`, userId: me.userId, userHandle: me.handle, kind:"debit", amount:p.amount, currency:p.currency, note: p.note || `Payment link created for @${to}`, counterpartyHandle: to, ts });

    const link = `${url.origin}/?claim=${encodeURIComponent(claimId)}`;
    audit("link.created", { claimId, fromUserId: me.userId, fromHandle: me.handle, toHandle: p.toHandle, amount: p.amount, currency: p.currency, link });
    return json(200, { claimId, url: link });
  }

  // claim
  if (pathname === "/api/claim" && req.method === "POST") {
    const me = await authUser(req);
    if (!me) return bad("unauthorized", 401);
    const { claimId } = await req.json().catch(()=> ({}));
    if (!claimId) return bad("claimId required");

    const r = await kv.get<Pending>(kPending(claimId));
    const p = r.value;
    if (!p) return bad("no such claim", 404);
    if (p.claimedAt) return bad("already claimed", 409);

    const meHandleLower = me.handle.toLowerCase();
    if (p.fromUserId === me.userId) return bad("cannot claim your own link", 400);
    if (p.toHandle !== meHandleLower) return bad(`link reserved for @${p.toHandle}`, 403);

    await kv.set(kPending(claimId), { ...p, claimedAt: nowSec(), claimedBy: me.userId });
    await creditBalance(me.userId, p.currency, +p.amount);

    const fromU = await getUserById(p.fromUserId);
    const fromHandle = fromU?.handle || "sender";
    const ts = nowSec();
    await recordTx({ id:`credit:${claimId}`, userId: me.userId, userHandle: me.handle, kind:"credit", amount:p.amount, currency:p.currency, note:p.note || `From @${fromHandle}`, counterpartyHandle: fromHandle, ts });

    audit("link.claimed", { claimId, byUserId: me.userId, byHandle: me.handle, toHandle: meHandleLower, amount: p.amount, currency: p.currency, fromHandle });
    return json(200, { ok:true, credited:{ amount:p.amount, currency:p.currency }, from: fromHandle });
  }

  // history
  if (pathname === "/api/history" && req.method === "GET") {
    const me = await authUser(req);
    if (!me) return bad("unauthorized", 401);
    const qs = new URL(req.url);
    const offset = Math.max(0, Number(qs.searchParams.get("offset") || "0"));
    const limit = Math.min(500, Math.max(1, Number(qs.searchParams.get("limit") || "100")));
    const all: Txn[] = [];
    for await (const e of kv.list<Txn>({ prefix: kTxPrefix(me.userId) })) if (e.value) all.push(e.value);
    all.sort((a,b)=> b.ts - a.ts);
    const slice = all.slice(offset, offset + limit);
    const hasOlder = offset + limit < all.length;
    const hasNewer = offset > 0;
    const balances: Record<string, number> = {};
    for await (const e of kv.list<number>({ prefix: ["balance", me.userId] })) balances[String(e.key[2])] = e.value ?? 0;
    return json(200, { balances, tx: slice, page: { offset, limit, total: all.length, hasOlder, hasNewer } });
  }

  return new Response("Not Found", { status: 404 });
});
