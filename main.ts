// Unbanked (Deno Deploy) — Balances in header, paginated history, mint-on-send
// - Serves index.html
// - Signup/Login (no email flows in UI)
// - Payment links never expire; claiming credits the receiver only (mint-on-send)
// - History endpoint supports pagination (?offset=&limit=)
// - Balances are per-user per-currency totals from claims (credits only)

const kv = await Deno.openKv();
const INDEX_HTML = await Deno.readTextFile(new URL("./index.html", import.meta.url));

type User = {
  userId: string;
  handle: string;          // unique
  secretHash: string;
  email?: string;          // optional, unused in this UI
  createdAt: number;
};

type Pending = {
  claimId: string;
  fromUserId: string;
  amount: number;
  currency: string;
  note: string;
  toLabel: string;
  createdAt: number;
  claimedAt?: number;
  claimedBy?: string;
};

type Txn = {
  id: string;
  userId: string;
  kind: "credit" | "debit";     // debit = sender "sent", credit = receiver "received"
  amount: number;
  currency: string;
  note: string;
  counterpartyHandle: string;
  ts: number;
};

// KV keys
const kUserByHandle = (h: string) => ["userByHandle", h] as const;
const kUserByEmail  = (e: string) => ["userByEmail", e]  as const;
const kUser         = (id: string) => ["user", id]        as const;
const kApiKey       = (apiKey: string) => ["apiKey", apiKey] as const;
const kPending      = (claimId: string) => ["pending", claimId] as const;
const kBalance      = (userId: string, cur: string) => ["balance", userId, cur] as const;
const kTxPrefix     = (userId: string) => ["tx", userId] as const;
const kTx           = (userId: string, ts: number, id: string) => ["tx", userId, ts, id] as const;

const enc = new TextEncoder();
function nowSec() { return Math.floor(Date.now()/1000); }
function uuid() { return crypto.randomUUID(); }
async function sha256(s: string) {
  const d = await crypto.subtle.digest("SHA-256", enc.encode(s));
  return [...new Uint8Array(d)].map(b=>b.toString(16).padStart(2,"0")).join("");
}
function json(status: number, body: unknown, headers: HeadersInit = {}) {
  return new Response(JSON.stringify(body), { status, headers: { "content-type":"application/json; charset=utf-8", ...headers } });
}
function bad(msg: string, status=400) { return json(status, { error: msg }); }

// Lookups
async function getUserByHandle(handle: string) {
  const id = await kv.get<string>(kUserByHandle(handle));
  if (!id.value) return null;
  const u = await kv.get<User>(kUser(id.value));
  return u.value ?? null;
}
async function getUserByEmail(email: string) {
  const id = await kv.get<string>(kUserByEmail(email));
  if (!id.value) return null;
  const u = await kv.get<User>(kUser(id.value));
  return u.value ?? null;
}
async function getUserByApiKey(apiKey: string) {
  const uid = await kv.get<string>(kApiKey(apiKey));
  if (!uid.value) return null;
  const u = await kv.get<User>(kUser(uid.value));
  return u.value ?? null;
}
async function authUser(req: Request) {
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
async function recordTx(t: Txn) { await kv.set(kTx(t.userId, t.ts, t.id), t); }

// HTTP
Deno.serve(async (req) => {
  const url = new URL(req.url);
  const { pathname } = url;

  // Static
  if (req.method === "GET" && (pathname === "/" || pathname === "/index.html")) {
    return new Response(INDEX_HTML, { headers: { "content-type":"text/html; charset=utf-8" } });
  }

  // CORS
  if (req.method === "OPTIONS") {
    return new Response("", {
      headers: {
        "access-control-allow-origin":"*",
        "access-control-allow-methods":"GET,POST,OPTIONS",
        "access-control-allow-headers":"content-type,authorization",
      }
    });
  }

  // ------- Auth -------
  if (pathname === "/api/signup" && req.method === "POST") {
    const b = await req.json().catch(()=> ({}));
    let { handle, secret, email, acceptedDisclaimer } = b;
    if (!handle || typeof handle!=="string") return bad("handle required");
    if (!secret || typeof secret!=="string" || secret.length<6) return bad("secret >= 6 chars required");
    if (!acceptedDisclaimer) return bad("accept disclaimer to continue");
    handle = String(handle).trim();

    const exists = await getUserByHandle(handle);
    if (exists) return bad("handle already taken", 409);

    let emailNorm: string|undefined = undefined;
    if (email) {
      emailNorm = String(email).toLowerCase().trim();
      const byEmail = await getUserByEmail(emailNorm);
      if (byEmail) return bad("email already in use", 409);
    }

    const userId = uuid();
    const secretHash = await sha256(secret);
    const user: User = { userId, handle, secretHash, email: emailNorm, createdAt: nowSec() };
    const apiKey = uuid();

    const tx = kv.atomic()
      .check({ key: kUserByHandle(handle), versionstamp: null })
      .set(kUserByHandle(handle), userId)
      .set(kUser(userId), user)
      .set(kApiKey(apiKey), userId);

    if (emailNorm) tx.check({ key: kUserByEmail(emailNorm), versionstamp: null }).set(kUserByEmail(emailNorm), userId);

    const ok = await tx.commit();
    if (!ok.ok) return bad("could not create user", 409);
    return json(200, { userId, apiKey, handle });
  }

  if (pathname === "/api/login" && req.method === "POST") {
    const b = await req.json().catch(()=> ({}));
    let { handle, email, secret } = b;
    if ((!handle && !email) || !secret) return bad("handle/email and secret required");
    let u: User | null = null;
    if (handle) u = await getUserByHandle(String(handle));
    else if (email) u = await getUserByEmail(String(email).toLowerCase().trim());
    if (!u) return bad("no such user", 404);
    const ok = (await sha256(secret)) === u.secretHash;
    if (!ok) return bad("invalid credentials", 401);
    const apiKey = uuid();
    await kv.set(kApiKey(apiKey), u.userId);
    return json(200, { userId: u.userId, apiKey, handle: u.handle });
  }

  // ------- Payments -------
  if (pathname === "/api/link" && req.method === "POST") {
    const me = await authUser(req);
    if (!me) return bad("unauthorized", 401);
    const { toLabel, amount, currency, note } = await req.json().catch(()=> ({}));
    const amt = Number(amount);
    const cur = String(currency || "").toUpperCase();
    if (!isFinite(amt) || amt<=0) return bad("amount must be > 0");
    if (!cur || cur.length<2 || cur.length>6) return bad("invalid currency code");

    const claimId = uuid();
    const p: Pending = {
      claimId, fromUserId: me.userId,
      amount:+amt.toFixed(8), currency:cur,
      note: String(note||""), toLabel: String(toLabel||""),
      createdAt: nowSec(),
    };
    await kv.set(kPending(claimId), p);

    // Record a "send" for the sender (for history) WITHOUT touching their balance
    const ts = nowSec();
    const txSend: Txn = {
      id:`send:${claimId}`,
      userId: me.userId,
      kind: "debit",
      amount: p.amount,
      currency: p.currency,
      note: p.note || `Payment link created`,
      counterpartyHandle: toLabel ? String(toLabel) : "",
      ts,
    };
    await recordTx(txSend);

    const link = `${url.origin}/?claim=${encodeURIComponent(claimId)}`;
    return json(200, { claimId, url: link });
  }

  if (pathname === "/api/claim" && req.method === "POST") {
    const me = await authUser(req);
    if (!me) return bad("unauthorized", 401);
    const { claimId } = await req.json().catch(()=> ({}));
    if (!claimId) return bad("claimId required");

    const r = await kv.get<Pending>(kPending(claimId));
    const p = r.value;
    if (!p) return bad("no such claim", 404);
    if (p.claimedAt) return bad("already claimed", 409);
    if (p.fromUserId === me.userId) return bad("cannot claim your own link", 400);

    const fromU = await kv.get<User>(kUser(p.fromUserId));
    const fromHandle = fromU.value?.handle || "sender";

    // Mark claimed, CREDIT receiver balance only (mint-on-send)
    await kv.set(kPending(claimId), { ...p, claimedAt: nowSec(), claimedBy: me.userId });
    await creditBalance(me.userId, p.currency, +p.amount);

    const ts = nowSec();
    // Receiver gets a credit txn
    const txCredit: Txn = {
      id:`credit:${claimId}`,
      userId: me.userId,
      kind:"credit",
      amount:p.amount,
      currency:p.currency,
      note:p.note || `From @${fromHandle}`,
      counterpartyHandle: fromHandle,
      ts,
    };
    await recordTx(txCredit);

    // Optional: also mark a "completed" send entry for the sender? (Already added at /api/link time.)

    return json(200, { ok:true, credited:{ amount:p.amount, currency:p.currency }, from: fromHandle });
  }

  // ------- History (paginated) -------
  // GET /api/history?offset=0&limit=100
  if (pathname === "/api/history" && req.method === "GET") {
    const me = await authUser(req);
    if (!me) return bad("unauthorized", 401);

    const offset = Math.max(0, Number(url.searchParams.get("offset") || "0"));
    const limit = Math.min(500, Math.max(1, Number(url.searchParams.get("limit") || "100"))); // cap at 500

    const all: Txn[] = [];
    for await (const e of kv.list<Txn>({ prefix: kTxPrefix(me.userId) })) {
      if (e.value) all.push(e.value);
    }
    all.sort((a,b)=> b.ts - a.ts);

    const slice = all.slice(offset, offset + limit);
    const hasOlder = offset + limit < all.length;
    const hasNewer = offset > 0;

    // balances: current totals
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
