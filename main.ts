// Unbanked — recipient-locked claims + mint-on-claim + single Authenticate + TX logging
// Deno Deploy entrypoint

const kv = await Deno.openKv();
const INDEX_HTML = await Deno.readTextFile(new URL("./index.html", import.meta.url));

type User = {
  userId: string;
  handle: string;          // preserved case; lookups are case-insensitive
  secretHash: string;
  createdAt: number;
};

type Pending = {
  claimId: string;
  fromUserId: string;
  toHandle: string;        // lowercase intended recipient
  amount: number;
  currency: string;
  note: string;
  createdAt: number;
  claimedAt?: number;
  claimedBy?: string;
};

type Txn = {
  id: string;
  userId: string;
  kind: "credit" | "debit";
  amount: number;
  currency: string;
  note: string;
  counterpartyHandle: string;
  ts: number;
};

// KV keys (handles stored lowercased)
const kUserByHandle = (h: string) => ["userByHandle", h.toLowerCase()] as const;
const kUser         = (id: string) => ["user", id] as const;
const kApiKey       = (apiKey: string) => ["apiKey", apiKey] as const;
const kPending      = (claimId: string) => ["pending", claimId] as const;
const kBalance      = (userId: string, cur: string) => ["balance", userId, cur] as const;
const kTxPrefix     = (userId: string) => ["tx", userId] as const;
const kTx           = (userId: string, ts: number, id: string) => ["tx", userId, ts, id] as const;

const enc = new TextEncoder();
function nowSec(){ return Math.floor(Date.now()/1000); }
function uuid(){ return crypto.randomUUID(); }
async function sha256(s: string){
  const d = await crypto.subtle.digest("SHA-256", enc.encode(s));
  return [...new Uint8Array(d)].map(b=>b.toString(16).padStart(2,"0")).join("");
}
function json(status: number, body: unknown, headers: HeadersInit = {}) {
  return new Response(JSON.stringify(body), { status, headers: { "content-type":"application/json; charset=utf-8", ...headers } });
}
function bad(msg: string, status=400){ return json(status, { error: msg }); }

// --------- Audit logging ---------
function audit(event: string, data: Record<string, unknown> = {}){
  // All TX-related and auth events printed to Deno Deploy logs
  console.log(JSON.stringify({ ts: nowSec(), evt: event, ...data }));
}

// Lookups / auth
async function getUserByHandle(handle: string): Promise<User|null> {
  const id = await kv.get<string>(kUserByHandle(handle));
  if (!id.value) return null;
  const u = await kv.get<User>(kUser(id.value));
  return u.value ?? null;
}
async function getUserByApiKey(apiKey: string): Promise<User|null> {
  const uid = await kv.get<string>(kApiKey(apiKey));
  if (!uid.value) return null;
  const u = await kv.get<User>(kUser(uid.value));
  return u.value ?? null;
}
async function authUser(req: Request){
  const a = req.headers.get("authorization") || "";
  const token = a.startsWith("Bearer ")? a.slice(7):"";
  return token ? getUserByApiKey(token) : null;
}

// Balance + TX helpers
async function creditBalance(userId: string, cur: string, amount: number) {
  const key = kBalance(userId, cur);
  for (let i=0;i<8;i++){
    const curVal = await kv.get<number>(key);
    const ver = curVal.versionstamp;
    const next = (curVal.value ?? 0) + amount;
    const res = await kv.atomic().check({ key, versionstamp: ver }).set(key, next).commit();
    if (res.ok) return next;
  }
  throw new Error("balance contention");
}
async function recordTx(t: Txn){
  await kv.set(kTx(t.userId, t.ts, t.id), t);
  audit("tx.recorded", { userId: t.userId, kind: t.kind, amount: t.amount, currency: t.currency, note: t.note, counterparty: t.counterpartyHandle, txId: t.id, ts: t.ts });
}

// HTTP
Deno.serve(async (req) => {
  const url = new URL(req.url);
  const { pathname } = url;

  // Static app
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

  // -------- Authenticate (login or create) --------
  // POST /api/authenticate {handle, secret, acceptedDisclaimer?}
  if (pathname === "/api/authenticate" && req.method === "POST") {
    const b = await req.json().catch(()=> ({}));
    const handle = String(b.handle||"").trim();
    const secret = String(b.secret||"");
    const accepted = !!b.acceptedDisclaimer;

    if (!handle || !secret) return bad("handle and secret required");

    const handleKey = handle.toLowerCase();
    if (!/^[a-z0-9_.-]{3,32}$/i.test(handle)) return bad("invalid handle");

    const existing = await getUserByHandle(handle);
    if (existing){
      const ok = (await sha256(secret)) === existing.secretHash;
      if (!ok){ audit("auth.fail", { handle }); return bad("invalid credentials", 401); }
      const apiKey = uuid();
      await kv.set(kApiKey(apiKey), existing.userId);
      audit("auth.login", { userId: existing.userId, handle: existing.handle });
      return json(200, { userId: existing.userId, apiKey, handle: existing.handle });
    } else {
      if (!accepted) return bad("accept disclaimer to create account");
      const userId = uuid();
      const user: User = { userId, handle, secretHash: await sha256(secret), createdAt: nowSec() };
      const apiKey = uuid();

      const ok = await kv.atomic()
        .check({ key: kUserByHandle(handleKey), versionstamp: null })
        .set(kUserByHandle(handleKey), userId)
        .set(kUser(userId), user)
        .set(kApiKey(apiKey), userId)
        .commit();

      if (!ok.ok) return bad("handle already taken", 409);
      audit("auth.signup", { userId, handle });
      return json(200, { userId, apiKey, handle });
    }
  }

  // -------- Payments --------
  // Create recipient-locked link
  if (pathname === "/api/link" && req.method === "POST") {
    const me = await authUser(req);
    if (!me) return bad("unauthorized", 401);
    const { toHandle, amount, currency, note } = await req.json().catch(()=> ({}));
    const amt = Number(amount);
    const cur = String(currency || "").toUpperCase();
    const to = String(toHandle || "").trim();
    if (!/^[a-z0-9_.-]{3,32}$/i.test(to)) return bad("valid toHandle required");
    if (!isFinite(amt) || amt<=0) return bad("amount must be > 0");
    if (!cur || cur.length<2 || cur.length>6) return bad("invalid currency code");

    const claimId = uuid();
    const p: Pending = {
      claimId,
      fromUserId: me.userId,
      toHandle: to.toLowerCase(),
      amount:+amt.toFixed(8),
      currency:cur,
      note: String(note||""),
      createdAt: nowSec(),
    };
    await kv.set(kPending(claimId), p);

    // Sender history only (no debit of balance)
    const ts = nowSec();
    await recordTx({
      id:`send:${claimId}`, userId: me.userId, kind: "debit",
      amount: p.amount, currency: p.currency,
      note: p.note || `Payment link created for @${to}`,
      counterpartyHandle: to, ts,
    });

    audit("link.created", { claimId, fromUserId: me.userId, toHandle: p.toHandle, amount: p.amount, currency: p.currency });
    const link = `${url.origin}/?claim=${encodeURIComponent(claimId)}`;
    return json(200, { claimId, url: link });
  }

  // Claim (must match intended handle)
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

    // Credit receiver (mint-on-claim). Sender's balance never decreases.
    await kv.set(kPending(claimId), { ...p, claimedAt: nowSec(), claimedBy: me.userId });
    await creditBalance(me.userId, p.currency, +p.amount);

    const fromU = await kv.get<User>(kUser(p.fromUserId));
    const fromHandle = fromU.value?.handle || "sender";
    const ts = nowSec();

    await recordTx({
      id:`credit:${claimId}`, userId: me.userId, kind:"credit",
      amount:p.amount, currency:p.currency,
      note:p.note || `From @${fromHandle}`, counterpartyHandle: fromHandle, ts,
    });

    audit("link.claimed", { claimId, byUserId: me.userId, toHandle: meHandleLower, amount: p.amount, currency: p.currency });
    return json(200, { ok:true, credited:{ amount:p.amount, currency:p.currency }, from: fromHandle });
  }

  // -------- History (paginated) --------
  // GET /api/history?offset=0&limit=100
  if (pathname === "/api/history" && req.method === "GET") {
    const me = await authUser(req);
    if (!me) return bad("unauthorized", 401);
    const offset = Math.max(0, Number(url.searchParams.get("offset") || "0"));
    const limit = Math.min(500, Math.max(1, Number(url.searchParams.get("limit") || "100")));

    const all: Txn[] = [];
    for await (const e of kv.list<Txn>({ prefix: kTxPrefix(me.userId) })) {
      if (e.value) all.push(e.value);
    }
    all.sort((a,b)=> b.ts - a.ts);
    const slice = all.slice(offset, offset + limit);
    const hasOlder = offset + limit < all.length;
    const hasNewer = offset > 0;

    const balances: Record<string, number> = {};
    for await (const e of kv.list<number>({ prefix: ["balance", me.userId] })) {
      const cur = String(e.key[2]);
      balances[cur] = e.value ?? 0;
    }

    return json(200, { balances, tx: slice, page: { offset, limit, total: all.length, hasOlder, hasNewer } });
  }

  // 404
  return new Response("Not Found", { status: 404 });
});
