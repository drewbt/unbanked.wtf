// Unbanked — stop history loss on re-login + instant receiver credit on link creation
// Deno Deploy entrypoint

const kv = await Deno.openKv();
const INDEX_HTML = await Deno.readTextFile(new URL("./index.html", import.meta.url));

// ---------------- Types ----------------
type User = { userId: string; handle: string; secretHash: string; createdAt: number; };
type Pending = {
  claimId: string;
  fromUserId: string;
  fromHandle: string;
  toUserId: string;
  toHandle: string;          // lowercase
  amount: number;
  currency: string;
  note: string;
  createdAt: number;
};
type Txn = {
  id: string;
  userId: string;
  userHandle: string;
  kind: "credit" | "debit";
  amount: number;
  currency: string;
  note: string;
  counterpartyHandle: string;
  ts: number;
};

// ---------------- KV Keys ----------------
const kUserByHandleLower = (h: string) => ["userByHandle", h.toLowerCase()] as const;
const kUserByHandleRaw   = (h: string) => ["userByHandle", h] as const; // legacy (old builds)
const kUser    = (id: string) => ["user", id] as const;
const kApiKey  = (apiKey: string) => ["apiKey", apiKey] as const;
const kPending = (claimId: string) => ["pending", claimId] as const;
const kBalance = (userId: string, cur: string) => ["balance", userId, cur] as const;
const kTxPrefix= (userId: string) => ["tx", userId] as const;
const kTx      = (userId: string, ts: number, id: string) => ["tx", userId, ts, id] as const;

// ---------------- Utils ----------------
const enc = new TextEncoder();
function nowSec(){ return Math.floor(Date.now()/1000); }
function uuid(){ return crypto.randomUUID(); }
async function sha256(s: string){ const d=await crypto.subtle.digest("SHA-256", enc.encode(s)); return [...new Uint8Array(d)].map(b=>b.toString(16).padStart(2,"0")).join(""); }
function json(status: number, body: unknown, headers: HeadersInit = {}){ return new Response(JSON.stringify(body), { status, headers: { "content-type":"application/json; charset=utf-8", ...headers } }); }
function bad(msg: string, status=400){ return json(status, { error: msg }); }
function audit(evt: string, data: Record<string, unknown> = {}){ console.log(JSON.stringify({ ts: nowSec(), evt, ...data })); }

// ---------------- Handle lookups (with legacy backfill) ----------------
async function getUserByHandle(handle: string): Promise<User|null> {
  const lc = handle.toLowerCase();
  // preferred: lowercase index
  let id = await kv.get<string>(kUserByHandleLower(lc));
  if (!id.value) {
    // legacy: raw key (old builds stored case-sensitive)
    const legacy = await kv.get<string>(kUserByHandleRaw(handle));
    if (legacy.value) {
      // backfill lower index → future reads stable
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

// ---------------- Balances & TX ----------------
async function creditBalance(userId: string, cur: string, amount: number){
  const key = kBalance(userId, cur);
  for (let i=0;i<12;i++){
    const curVal = await kv.get<number>(key);
    const ver = curVal.versionstamp; // null ok for first write
    const next = (curVal.value ?? 0) + amount;
    const res = await kv.atomic().check({ key, versionstamp: ver }).set(key, next).commit();
    if (res.ok) return next;
  }
  throw new Error("balance contention");
}
async function recordTx(t: Txn){
  await kv.set(kTx(t.userId, t.ts, t.id), t);
  audit("tx.recorded", { userId:t.userId, userHandle:t.userHandle, kind:t.kind, amount:t.amount, currency:t.currency, counterparty:t.counterpartyHandle, id:t.id, ts:t.ts });
}

// ---------------- HTTP ----------------
Deno.serve(async (req) => {
  const url = new URL(req.url);
  const { pathname } = url;

  // Static
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

  // -------- Authenticate (login-or-create) with duplicate-handle guard --------
  // POST /api/authenticate {handle, secret, acceptedDisclaimer?}
  if (pathname === "/api/authenticate" && req.method === "POST") {
    const b = await req.json().catch(()=> ({}));
    const handle = String(b.handle||"").trim();
    const secret = String(b.secret||"");
    const accepted = !!b.acceptedDisclaimer;

    if (!handle || !secret) return bad("handle and secret required");
    if (!/^[a-z0-9_.-]{3,32}$/i.test(handle)) return bad("invalid handle");

    // If exists → login
    const existing = await getUserByHandle(handle);
    if (existing){
      const ok = (await sha256(secret)) === existing.secretHash;
      if (!ok){ audit("auth.fail", { handle }); return bad("invalid credentials", 401); }
      const apiKey = uuid(); await kv.set(kApiKey(apiKey), existing.userId);
      audit("auth.login", { userId: existing.userId, handle: existing.handle });
      return json(200, { userId: existing.userId, apiKey, handle: existing.handle });
    }

    // Create new (only if neither lowercase nor legacy key is taken)
    if (!accepted) return bad("accept disclaimer to create account");
    const lc = handle.toLowerCase();
    const userId = uuid();
    const user: User = { userId, handle, secretHash: await sha256(secret), createdAt: nowSec() };
    const apiKey = uuid();

    const ok = await kv.atomic()
      .check({ key: kUserByHandleLower(lc), versionstamp: null })
      .check({ key: kUserByHandleRaw(handle),  versionstamp: null }) // guard against legacy duplicates
      .set(kUserByHandleLower(lc), userId)
      .set(kUser(userId), user)
      .set(kApiKey(apiKey), userId)
      .commit();

    if (!ok.ok) return bad("handle already taken", 409);
    audit("auth.signup", { userId, handle });
    return json(200, { userId, apiKey, handle });
  }

  // -------- Create link = instant receiver credit (link is just a share) --------
  // POST /api/link { toHandle, amount, currency, note }
  if (pathname === "/api/link" && req.method === "POST") {
    const me = await authUser(req);
    if (!me) { audit("link.err.unauth", {}); return bad("unauthorized", 401); }

    const b = await req.json().catch(()=> ({}));
    let to = String(b.toHandle||"").trim();
    if (to.startsWith("@")) to = to.slice(1);
    const rawAmt = String(b.amount ?? "").replace(/\s+/g,"").replace(",",".");
    const amount = Number(rawAmt);
    const currency = String(b.currency||"").trim().toUpperCase();
    const note = String(b.note||"").trim();

    if (!/^[a-z0-9_.-]{3,32}$/i.test(to)) return bad("valid toHandle required (letters, numbers, _ . -)");
    if (!isFinite(amount) || amount<=0) return bad("amount must be > 0");
    if (!/^[A-Z0-9]{2,6}$/.test(currency)) return bad("invalid currency code");

    // Recipient must exist to reflect instantly
    const rec = await getUserByHandle(to);
    if (!rec) return bad("recipient not found", 404);

    const claimId = uuid();
    const p: Pending = {
      claimId,
      fromUserId: me.userId,
      fromHandle: me.handle,
      toUserId: rec.userId,
      toHandle: to.toLowerCase(),
      amount:+amount.toFixed(8),
      currency,
      note,
      createdAt: nowSec(),
    };
    await kv.set(kPending(claimId), p);

    // Write TX on both sides (instant reflect); sender is not debited (mint-on-send)
    const ts = nowSec();

    await recordTx({
      id:`send:${claimId}`, userId: me.userId, userHandle: me.handle, kind:"debit",
      amount:p.amount, currency:p.currency, note: p.note || `Payment link created for @${rec.handle}`,
      counterpartyHandle: rec.handle, ts
    });

    await creditBalance(rec.userId, p.currency, +p.amount);
    await recordTx({
      id:`credit:${claimId}`, userId: rec.userId, userHandle: rec.handle, kind:"credit",
      amount:p.amount, currency:p.currency, note: p.note || `From @${me.handle}`,
      counterpartyHandle: me.handle, ts
    });

    const link = `${url.origin}/?ref=${encodeURIComponent(claimId)}`; // purely informational
    audit("link.created.instantCredit", { claimId, fromHandle: me.handle, toHandle: rec.handle, amount: p.amount, currency: p.currency, link });

    return json(200, { claimId, url: link });
  }

  // -------- Claim endpoint (no-op; kept for old links) --------
  // POST /api/claim { claimId }
  if (pathname === "/api/claim" && req.method === "POST") {
    // No-op now: credit already applied on link creation
    const { claimId } = await req.json().catch(()=> ({}));
    const row = await kv.get<Pending>(kPending(String(claimId||"")));
    if (!row.value) return bad("no such link", 404);
    return json(200, { ok:true, info:"already reflected", claimId });
  }

  // -------- History (server-side; shared across devices) --------
  // GET /api/history?offset=&limit=
  if (pathname === "/api/history" && req.method === "GET") {
    const me = await authUser(req);
    if (!me) return bad("unauthorized", 401);
    const offset = Math.max(0, Number(url.searchParams.get("offset") || "0"));
    const limit  = Math.min(500, Math.max(1, Number(url.searchParams.get("limit") || "100")));

    const all: Txn[] = [];
    for await (const e of kv.list<Txn>({ prefix: kTxPrefix(me.userId) })) if (e.value) all.push(e.value);
    all.sort((a,b)=> b.ts - a.ts);
    const slice = all.slice(offset, offset + limit);

    const balances: Record<string, number> = {};
    for await (const e of kv.list<number>({ prefix: ["balance", me.userId] })) balances[String(e.key[2])] = e.value ?? 0;

    return json(200, {
      balances,
      tx: slice,
      page: { offset, limit, total: all.length, hasOlder: offset + limit < all.length, hasNewer: offset > 0 }
    });
  }

  return new Response("Not Found", { status: 404 });
});
