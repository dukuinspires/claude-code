/**
 * DeepSeek Web Proxy — Token Pool Edition
 *
 * Maintains a pool of DeepSeek accounts. On 40003 (expired/invalid token),
 * immediately rotates to the next active account — no re-login delay,
 * no downtime. Background re-login refreshes cooled accounts back into rotation.
 *
 * Pool is hot-reloadable via POST /admin/reload-pool (no restart needed).
 *
 * Env:
 *   DS_PROXY_PORT      — port (default 3098)
 *   DS_POOL_JSON       — JSON array of {token,email,password,dliq,leim} for initial pool
 *   INTERNAL_AUTH_TOKEN — admin endpoint auth
 *   SMARTASSIST_URL    — for persisting tokens back to SmartAssist after re-login
 *   VPS_PROXY_URL      — VPS base URL for routing login calls through clean IP
 *   SMTP_PROXY_SECRET  — auth secret for VPS /ds-proxy endpoint
 */

import { readFileSync } from "fs";

const PORT = process.env.DS_PROXY_PORT ? parseInt(process.env.DS_PROXY_PORT) : 3098;
const DS_API = "https://chat.deepseek.com";
const INTERNAL_TOKEN = process.env.INTERNAL_AUTH_TOKEN || "";

// ─── Request counter for access logging ──────────────────────────────────────
let requestCount = 0;

function reqId() {
  return `req-${++requestCount}`;
}

// ─── GCP identity token for Cloud Run → SmartAssist callbacks ─────────────────
let _saTokenCache: { token: string; expiresAt: number } | null = null;
async function getSmartAssistIdToken(): Promise<string | null> {
  if (!process.env.K_SERVICE) return null; // local dev — no auth needed
  const saUrl = process.env.SMARTASSIST_URL || "";
  if (!saUrl) return null;
  const now = Date.now();
  if (_saTokenCache && _saTokenCache.expiresAt > now + 60_000) {
    console.log("[ds-proxy] [gcp-token] using cached identity token");
    return _saTokenCache.token;
  }
  try {
    console.log("[ds-proxy] [gcp-token] fetching new identity token from metadata server");
    const res = await fetch(
      `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=${encodeURIComponent(saUrl)}`,
      { headers: { "Metadata-Flavor": "Google" } }
    );
    if (!res.ok) {
      console.warn(`[ds-proxy] [gcp-token] metadata server returned HTTP ${res.status}`);
      return null;
    }
    const token = await res.text();
    _saTokenCache = { token, expiresAt: now + 50 * 60_000 };
    console.log(`[ds-proxy] [gcp-token] ✓ obtained (${token.length} chars, expires in 50min)`);
    return token;
  } catch (e: any) {
    console.warn(`[ds-proxy] [gcp-token] ✗ failed: ${e.message}`);
    return null;
  }
}

// ─── Account pool ─────────────────────────────────────────────────────────────

// ─── Rate limit intelligence (empirical data from 165K request analysis) ──────
// DeepSeek throttles at ~18 req/min sustained per account. Progressive tightening:
// first offence gets 19min, repeat offenders get <1min before re-block.
// Soft throttle signal: chars=0 responses (HTTP 200 but empty content).
// Token is never revoked — only throttled. Full reset after traffic normalises.
const THROTTLE_WINDOW_MS = 60_000;  // 1 minute window
const THROTTLE_MAX_REQ   = 16;     // conservative: 16 req/min (under 18 limit)

// Progressive cooldown: increases with consecutive failures to match DeepSeek's
// cumulative memory. Fixed 10min was too short — DeepSeek remembers repeat offenders.
const COOLDOWN_BASE_MS   = 10 * 60 * 1000;  // 10 minutes (first failure)
const COOLDOWN_MAX_MS    = 60 * 60 * 1000;  // 60 minutes (max)
const COOLDOWN_MULTIPLIER = 1.5;             // each failure: 10 → 15 → 22 → 34 → 50 → 60 min

interface PoolAccount {
  token: string;
  email?: string;
  password?: string;  // stored encrypted in DB, decrypted before loading into pool
  dliq?: string;
  leim?: string;
  status: "active" | "cooling" | "dead";
  failureCount: number;
  lastUsed: number;
  coolingUntil?: number;
  // Sliding window request timestamps for proactive throttle
  recentRequests: number[];
  // Token lifecycle tracking — learn actual TTL from 40003 expiry events
  tokenObtainedAt?: number;
  // Rate limit detection: consecutive empty responses (chars=0)
  consecutiveEmpties: number;
  // Total successful responses with content (for stats)
  totalWithContent: number;
  totalEmpty: number;
}

// ─── Token lifetime tracking ─────────────────────────────────────────────────
// Records observed token lifetimes (ms) when 40003 fires. Over time, the median
// tells us the actual TTL so we can proactively refresh before expiry.
const tokenLifetimeObservations: number[] = [];

function recordTokenExpiry(acc: PoolAccount) {
  if (!acc.tokenObtainedAt) return;
  const lifetimeMs = Date.now() - acc.tokenObtainedAt;
  const lifetimeH = (lifetimeMs / 3_600_000).toFixed(1);
  tokenLifetimeObservations.push(lifetimeMs);
  // Keep last 50 observations
  if (tokenLifetimeObservations.length > 50) tokenLifetimeObservations.shift();
  const medianMs = tokenLifetimeObservations.length > 0
    ? tokenLifetimeObservations.slice().sort((a, b) => a - b)[Math.floor(tokenLifetimeObservations.length / 2)]
    : null;
  const medianH = medianMs ? (medianMs / 3_600_000).toFixed(1) : "?";
  console.log(`[ds-proxy] [token-ttl] ${acc.email || "??"}: token expired after ${lifetimeH}h | observations=${tokenLifetimeObservations.length} median=${medianH}h`);
}

let pool: PoolAccount[] = [];

function poolSummary() {
  return {
    total: pool.length,
    active: pool.filter(a => a.status === "active").length,
    cooling: pool.filter(a => a.status === "cooling").length,
    dead: pool.filter(a => a.status === "dead").length,
  };
}

function initPoolFromEnv() {
  console.log("[ds-proxy] [init] ── initPoolFromEnv ──────────────────────────");
  console.log(`[ds-proxy] [init]   DS_POOL_JSON       = ${process.env.DS_POOL_JSON ? `set (${process.env.DS_POOL_JSON.length} chars)` : "unset"}`);
  console.log(`[ds-proxy] [init]   DS_USER_TOKEN      = ${process.env.DS_USER_TOKEN ? "set" : "unset"}`);
  console.log(`[ds-proxy] [init]   SMARTASSIST_URL    = ${process.env.SMARTASSIST_URL || "unset"}`);
  console.log(`[ds-proxy] [init]   INTERNAL_AUTH_TOKEN= ${process.env.INTERNAL_AUTH_TOKEN ? "set" : "unset"}`);
  console.log(`[ds-proxy] [init]   VPS_PROXY_URL      = ${process.env.VPS_PROXY_URL || "unset"}`);
  console.log(`[ds-proxy] [init]   SMTP_PROXY_SECRET  = ${process.env.SMTP_PROXY_SECRET ? "set" : "unset"}`);
  console.log(`[ds-proxy] [init]   K_SERVICE          = ${process.env.K_SERVICE || "unset (local)"}`);

  // Bootstrap from DS_POOL_JSON env (JSON array loaded by SmartAssist on startup)
  try {
    const raw = process.env.DS_POOL_JSON;
    if (raw) {
      const accounts = JSON.parse(raw) as any[];
      console.log(`[ds-proxy] [init] DS_POOL_JSON parsed — ${accounts.length} entry(s)`);
      pool = accounts.map(a => ({
        token: a.token || "",
        email: a.email,
        password: a.password,
        dliq: a.dliq || a.hif_dliq,
        leim: a.leim || a.hif_leim,
        status: a.token ? "active" : "cooling" as any,
        failureCount: 0,
        lastUsed: 0,
        recentRequests: [],
        tokenObtainedAt: a.token_obtained_at ? new Date(a.token_obtained_at).getTime() : Date.now(),
        consecutiveEmpties: 0,
        totalWithContent: 0,
        totalEmpty: 0,
      }));
      const active = pool.filter(a => a.status === "active").length;
      console.log(`[ds-proxy] [init] ✓ Loaded ${pool.length} account(s) from DS_POOL_JSON (${active} active)`);
      pool.forEach(a => console.log(
        `[ds-proxy] [init]   • ${a.email || "unknown"} | status=${a.status} | hasToken=${!!a.token} | hasDliq=${!!a.dliq} | hasLeim=${!!a.leim} | hasPassword=${!!a.password}`
      ));
      return;
    }
  } catch (e) {
    console.error("[ds-proxy] [init] ✗ Failed to parse DS_POOL_JSON:", e);
  }

  // Fallback: single-account mode from legacy env vars
  const token = process.env.DS_USER_TOKEN || "";
  if (token) {
    pool = [{
      token,
      email: process.env.DS_EMAIL,
      password: process.env.DS_PASSWORD,
      dliq: process.env.DS_HIF_DLIQ,
      leim: process.env.DS_HIF_LEIM,
      status: "active",
      failureCount: 0,
      lastUsed: 0,
      recentRequests: [],
      consecutiveEmpties: 0,
      totalWithContent: 0,
      totalEmpty: 0,
    }];
    console.log(`[ds-proxy] [init] ✓ Loaded 1 account from DS_USER_TOKEN (email=${process.env.DS_EMAIL || "unknown"})`);
  } else {
    console.warn("[ds-proxy] [init] ⚠ No DS_POOL_JSON or DS_USER_TOKEN — pool empty until SmartAssist sync");
  }
}

initPoolFromEnv();

/** On startup: if pool is empty, pull stored tokens from SmartAssist automatically.
 *  This is the primary bootstrap path — no env vars needed. */
async function syncPoolFromSmartAssist() {
  const saUrl = process.env.SMARTASSIST_URL || "";
  const internalTok = process.env.INTERNAL_AUTH_TOKEN || "";
  console.log(`[ds-proxy] [sync] ── syncPoolFromSmartAssist ──────────────────`);
  console.log(`[ds-proxy] [sync]   saUrl=${saUrl || "unset"} internalTok=${internalTok ? "set" : "unset"}`);

  if (!saUrl) {
    console.warn("[ds-proxy] [sync] ⚠ SMARTASSIST_URL not set — cannot auto-sync pool");
    return;
  }
  if (!internalTok) {
    console.warn("[ds-proxy] [sync] ⚠ INTERNAL_AUTH_TOKEN not set — cannot authenticate to SmartAssist");
    return;
  }

  const syncUrl = `${saUrl}/api/webhooks/ds-proxy-sync`;
  console.log(`[ds-proxy] [sync] calling ${syncUrl} …`);

  try {
    const t0 = Date.now();
    const idToken = await getSmartAssistIdToken();
    console.log(`[ds-proxy] [sync] GCP identity token: ${idToken ? `obtained (${idToken.length} chars)` : "not available (local dev)"}`);

    const res = await fetch(syncUrl, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-internal-token": internalTok,
        ...(idToken ? { "Authorization": `Bearer ${idToken}` } : {}),
      },
    });
    const elapsed = Date.now() - t0;
    console.log(`[ds-proxy] [sync] SmartAssist responded HTTP ${res.status} in ${elapsed}ms`);

    if (res.ok) {
      const data = await res.json() as any;
      console.log(`[ds-proxy] [sync] ✓ result: ${JSON.stringify(data)}`);
      const s = poolSummary();
      console.log(`[ds-proxy] [sync] pool after sync — total=${s.total} active=${s.active} cooling=${s.cooling} dead=${s.dead}`);
    } else {
      const body = await res.text().catch(() => "");
      console.warn(`[ds-proxy] [sync] ⚠ HTTP ${res.status} — starting with empty pool. Body: ${body.slice(0, 300)}`);
    }
  } catch (e: any) {
    console.warn(`[ds-proxy] [sync] ⚠ sync failed (non-fatal): ${e.message}`);
  }
}

// Bootstrap: ALWAYS sync from SmartAssist on startup to pick up all accounts.
// Even if DS_USER_TOKEN provides 1 account, the DB may have more (e.g. 3-4 accounts
// registered via OAuth). The sync merges DB accounts into the pool without dropping
// any that were loaded from env vars.
const envPoolSize = pool.length;
console.log(`[ds-proxy] [init] post-init pool — size=${envPoolSize} from env`);
console.log("[ds-proxy] [init] triggering SmartAssist auto-sync to load all DB accounts");
syncPoolFromSmartAssist();

// Periodic sync handled by SmartAssist Cloud Tasks cron job (ds-proxy-sync every 15min).
// No setInterval needed — SmartAssist pushes tokens to the proxy on schedule.

/** Prune old timestamps and return current request count in the sliding window */
function windowCount(acc: PoolAccount): number {
  const cutoff = Date.now() - THROTTLE_WINDOW_MS;
  acc.recentRequests = acc.recentRequests.filter(t => t > cutoff);
  return acc.recentRequests.length;
}

/** Record a request against an account's sliding window */
function recordRequest(acc: PoolAccount) {
  acc.recentRequests.push(Date.now());
}

/** Pick the next active account from the pool (LRU, skips cooling/dead/throttled) */
function pickAccount(): PoolAccount | null {
  const now = Date.now();

  // Thaw any accounts whose cooling period has ended
  for (const acc of pool) {
    if (acc.status === "cooling" && acc.coolingUntil && now >= acc.coolingUntil) {
      acc.status = "active";
      acc.coolingUntil = undefined;
      acc.consecutiveEmpties = 0; // Reset empty counter on thaw
      console.log(`[ds-proxy] [pool] ♻ Thawed ${acc.email || "??"} back to active (failures=${acc.failureCount})`);
    }
  }

  // Active accounts that are under the proactive throttle threshold
  const actives = pool.filter(a => a.status === "active" && a.token && windowCount(a) < THROTTLE_MAX_REQ);
  if (!actives.length) {
    // All active accounts are at the throttle limit — DO NOT exceed.
    // Exceeding triggers DeepSeek's progressive tightening which makes things worse.
    // Return null so the caller gets a 503 and runLLM falls back to another provider.
    const anyActive = pool.filter(a => a.status === "active" && a.token);
    if (!anyActive.length) {
      const s = poolSummary();
      console.warn(`[ds-proxy] [pool] ✗ no active accounts — total=${s.total} cooling=${s.cooling} dead=${s.dead}`);
    } else {
      console.warn(`[ds-proxy] [pool] ⚠ all ${anyActive.length} account(s) at throttle limit (${THROTTLE_MAX_REQ} req/min) — returning 503 to trigger fallback`);
    }
    return null;
  }

  // Prefer least-recently-used among unthrottled accounts
  actives.sort((a, b) => a.lastUsed - b.lastUsed);
  return actives[0];
}

/** Mark an account as cooling (rate-limited). Progressive cooldown to match
 *  DeepSeek's cumulative memory. Does NOT trigger re-login (rate limit = same
 *  token is fine, just needs rest). */
function coolAccount(acc: PoolAccount) {
  acc.status = "cooling";
  acc.failureCount++;
  // Progressive cooldown: 10 → 15 → 22 → 34 → 50 → 60 min (capped)
  const cooldownMs = Math.min(
    COOLDOWN_BASE_MS * Math.pow(COOLDOWN_MULTIPLIER, acc.failureCount - 1),
    COOLDOWN_MAX_MS
  );
  acc.coolingUntil = Date.now() + cooldownMs;
  const cooldownMin = (cooldownMs / 60_000).toFixed(0);
  const s = poolSummary();
  const ageH = acc.tokenObtainedAt ? ((Date.now() - acc.tokenObtainedAt) / 3_600_000).toFixed(1) + "h" : "?";
  console.log(`[ds-proxy] [pool] ❄ Cooled ${acc.email || "??"} for ${cooldownMin}min (failures=${acc.failureCount} tokenAge=${ageH} empties=${acc.consecutiveEmpties}) — pool: active=${s.active} cooling=${s.cooling} dead=${s.dead}`);
}

/** Mark an account as expired (40003 token invalid). Triggers re-login to get a fresh token. */
function expireAccount(acc: PoolAccount) {
  recordTokenExpiry(acc);
  coolAccount(acc);
  // Trigger background re-login — VPS OAuth doesn't need a password
  if (acc.email) {
    console.log(`[ds-proxy] [pool] → triggering background re-login for ${acc.email} (hasPassword=${!!acc.password})`);
    reloginAccount(acc).catch(() => {});
  } else {
    console.warn(`[ds-proxy] [pool] ⚠ account has no email — cannot auto re-login`);
  }
}

// ─── VPS fetch helper — routes DeepSeek API calls through clean IP ───────────
//
// Login/re-login calls from Cloud Run trigger RISK_DEVICE_DETECTED (biz_code=11)
// because Cloud Run egress IPs are flagged. Route them through the VPS instead.

async function vdsFetch(path: string, init: { method: string; headers: Record<string, string>; body: string }): Promise<Response> {
  const vpsUrl = process.env.VPS_PROXY_URL || "";
  const secret = process.env.SMTP_PROXY_SECRET || "";

  if (vpsUrl) {
    const t0 = Date.now();
    console.log(`[ds-proxy] [vps-fetch] → ${init.method} ${path} via VPS ${vpsUrl}`);
    try {
      const res = await fetch(`${vpsUrl}/ds-proxy`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-smtp-proxy-secret": secret,
        },
        body: JSON.stringify({ path, method: init.method, headers: init.headers, body: init.body }),
      });
      const elapsed = Date.now() - t0;
      if (res.ok) {
        const json = await res.json() as any;
        console.log(`[ds-proxy] [vps-fetch] ✓ VPS responded in ${elapsed}ms → upstream status=${json.status}`);
        return new Response(json.body, { status: json.status });
      }
      console.warn(`[ds-proxy] [vps-fetch] ⚠ VPS HTTP ${res.status} in ${elapsed}ms — falling back to direct`);
    } catch (e: any) {
      console.warn(`[ds-proxy] [vps-fetch] ⚠ VPS error: ${e.message} — falling back to direct`);
    }
  } else {
    console.warn(`[ds-proxy] [vps-fetch] VPS_PROXY_URL not set — calling DeepSeek directly (may trigger RISK_DEVICE_DETECTED)`);
  }

  // Fallback: direct (local dev or VPS unavailable)
  console.log(`[ds-proxy] [vps-fetch] → ${init.method} ${path} direct to DeepSeek`);
  return fetch(`${DS_API}${path}`, { method: init.method, headers: init.headers, body: init.body });
}

// ─── DeepSeek login ───────────────────────────────────────────────────────────

async function loginDeepSeek(email: string, password: string, deviceId?: string): Promise<string | null> {
  const did = deviceId || `sa-proxy-${email.replace(/[^a-z0-9]/gi, "").slice(0, 12)}`;
  console.log(`[ds-proxy] [login] attempting login for ${email} (deviceId=${did})`);
  try {
    const headers = {
      "content-type": "application/json",
      "x-app-version": "20241129.1",
      "x-client-platform": "web",
      "x-client-version": "1.8.0",
      "user-agent": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Mobile Safari/537.36",
      "origin": "https://chat.deepseek.com",
      "referer": "https://chat.deepseek.com/",
    };
    const body = JSON.stringify({ email, password, device_id: did, os: "web" });
    const res = await vdsFetch("/api/v0/users/login", { method: "POST", headers, body });
    const data = await res.json() as any;
    const token = data?.data?.biz_data?.user?.token ?? null;
    const bizCode = data?.code ?? data?.data?.code;
    const bizMsg = data?.data?.biz_msg ?? data?.message ?? "";
    console.log(`[ds-proxy] [login] ${email} — bizCode=${bizCode} bizMsg=${bizMsg} hasToken=${!!token}`);
    if (bizCode === 11) console.error(`[ds-proxy] [login] ✗ RISK_DEVICE_DETECTED for ${email} — VPS IP may be flagged`);
    return token;
  } catch (e: any) {
    console.error(`[ds-proxy] [login] ✗ threw for ${email}: ${e.message}`);
    return null;
  }
}

/** Try VPS OAuth relogin first (same flow that registered accounts successfully).
 *  Falls back to password login if VPS OAuth is unavailable. */
async function reloginViaVpsOAuth(email: string): Promise<string | null> {
  const vpsUrl = process.env.VPS_PROXY_URL;
  const vpsSecret = process.env.SMTP_PROXY_SECRET;
  if (!vpsUrl || !vpsSecret) {
    console.log(`[ds-proxy] [relogin-oauth] VPS_PROXY_URL or SMTP_PROXY_SECRET not set — skipping OAuth path`);
    return null;
  }
  const oauthUrl = `${vpsUrl}/ds-oauth/register`;
  console.log(`[ds-proxy] [relogin-oauth] calling VPS OAuth for ${email}: ${oauthUrl}`);
  try {
    const t0 = Date.now();
    const res = await fetch(oauthUrl, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-smtp-proxy-secret": vpsSecret,
      },
      body: JSON.stringify({ email, mode: "relogin" }),
      signal: AbortSignal.timeout(120_000), // VPS OAuth can take up to 60s
    });
    const elapsed = Date.now() - t0;
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      console.warn(`[ds-proxy] [relogin-oauth] VPS HTTP ${res.status} in ${elapsed}ms — ${body.slice(0, 200)}`);
      return null;
    }
    const data = await res.json() as any;
    const token = data?.token || data?.data?.token;
    console.log(`[ds-proxy] [relogin-oauth] ${token ? "✓" : "✗"} VPS OAuth ${token ? "succeeded" : "failed"} for ${email} in ${elapsed}ms`);
    return token || null;
  } catch (e: any) {
    console.error(`[ds-proxy] [relogin-oauth] ✗ VPS OAuth threw for ${email}: ${e.message}`);
    return null;
  }
}

async function reloginAccount(acc: PoolAccount) {
  if (!acc.email) return;
  console.log(`[ds-proxy] [relogin] 🔑 re-logging in ${acc.email} (failures=${acc.failureCount})`);
  const t0 = Date.now();

  // Try VPS OAuth first (same flow that successfully registered accounts)
  let newToken = await reloginViaVpsOAuth(acc.email);

  // Fallback: password login via VPS (may get RISK_DEVICE_DETECTED)
  if (!newToken && acc.password) {
    console.log(`[ds-proxy] [relogin] VPS OAuth failed — trying password login for ${acc.email}`);
    newToken = await loginDeepSeek(acc.email, acc.password);
  }
  const elapsed = Date.now() - t0;

  if (newToken) {
    acc.token = newToken;
    acc.status = "active";
    acc.failureCount = 0;
    acc.coolingUntil = undefined;
    acc.tokenObtainedAt = Date.now();
    acc.consecutiveEmpties = 0;
    acc.totalWithContent = 0;
    acc.totalEmpty = 0;
    console.log(`[ds-proxy] [relogin] ✓ re-login succeeded for ${acc.email} in ${elapsed}ms`);

    // Persist back to SmartAssist with retries — token loss here means it's gone on restart
    const saUrl = process.env.SMARTASSIST_URL || "";
    const internalTok = process.env.INTERNAL_AUTH_TOKEN || "";
    if (saUrl && internalTok) {
      console.log(`[ds-proxy] [relogin] persisting new token for ${acc.email} → SmartAssist`);
      (async () => {
        const idToken = await getSmartAssistIdToken();
        const headers: Record<string, string> = {
          "content-type": "application/json",
          "x-internal-token": internalTok,
          ...(idToken ? { "Authorization": `Bearer ${idToken}` } : {}),
        };
        const body = JSON.stringify({ token: newToken, email: acc.email });
        const persistUrl = `${saUrl}/api/admin/deepseek-proxy/reload-tokens`;

        for (let attempt = 1; attempt <= 3; attempt++) {
          try {
            const r = await fetch(persistUrl, { method: "POST", headers, body });
            if (r.ok) {
              console.log(`[ds-proxy] [relogin] ✓ SmartAssist token persist HTTP ${r.status} for ${acc.email} (attempt ${attempt})`);
              return;
            }
            console.warn(`[ds-proxy] [relogin] ⚠ SmartAssist persist HTTP ${r.status} for ${acc.email} (attempt ${attempt}/3)`);
          } catch (e: any) {
            console.error(`[ds-proxy] [relogin] ✗ SmartAssist persist attempt ${attempt}/3 failed for ${acc.email}: ${e.message}`);
          }
          if (attempt < 3) await new Promise(r => setTimeout(r, attempt * 2000));
        }
        console.error(`[ds-proxy] [relogin] ✗✗ CRITICAL: token for ${acc.email} NOT persisted after 3 attempts — will be lost on restart`);
      })();
    } else {
      console.warn(`[ds-proxy] [relogin] ⚠ SMARTASSIST_URL or INTERNAL_AUTH_TOKEN not set — new token not persisted for ${acc.email}`);
    }
  } else {
    console.error(`[ds-proxy] [relogin] ✗ re-login failed for ${acc.email} in ${elapsed}ms (failures now=${acc.failureCount})`);
    if (acc.failureCount >= 3) {
      acc.status = "dead";
      console.error(`[ds-proxy] [relogin] 💀 ${acc.email} marked dead after ${acc.failureCount} failures`);
    }
  }
}

// ─── Load WASM PoW solver ─────────────────────────────────────────────────────
const wasmPath = process.env.DS_WASM_PATH || new URL("./deepseek-wasm/sha3_wasm_bg.wasm", import.meta.url).pathname;
console.log(`[ds-proxy] [wasm] loading from ${wasmPath}`);
const wasmBytes = readFileSync(wasmPath);
const { instance: wasmInstance } = await WebAssembly.instantiate(wasmBytes);
console.log(`[ds-proxy] [wasm] ✓ loaded (${wasmBytes.length} bytes)`);
const {
  wasm_solve,
  __wbindgen_add_to_stack_pointer,
  __wbindgen_export_0: wasm_malloc,
  memory: wasmMemory,
} = wasmInstance.exports as any;

const enc = new TextEncoder();
let _wasmVecLen = 0;

function passStrToWasm(str: string): number {
  const buf = enc.encode(str);
  const ptr = wasm_malloc(buf.length, 1);
  new Uint8Array(wasmMemory.buffer).set(buf, ptr);
  _wasmVecLen = buf.length;
  return ptr;
}

function solvePoW(challenge: string, salt: string, difficulty: number, expireAt: number): number | null {
  const prefix = `${salt}_${expireAt}_`;
  const retptr = __wbindgen_add_to_stack_pointer(-16);
  const challengePtr = passStrToWasm(challenge);
  const challengeLen = _wasmVecLen;
  const prefixPtr = passStrToWasm(prefix);
  const prefixLen = _wasmVecLen;
  try {
    wasm_solve(retptr, challengePtr, challengeLen, prefixPtr, prefixLen, difficulty);
    const view = new DataView(wasmMemory.buffer);
    const ok = view.getInt32(retptr, true);
    const answer = view.getFloat64(retptr + 8, true);
    return ok !== 0 ? answer : null;
  } finally {
    __wbindgen_add_to_stack_pointer(16);
  }
}

// ─── PoW challenge fetch + solve ─────────────────────────────────────────────
async function getPowResponse(targetPath: string, token: string): Promise<string | null> {
  const t0 = Date.now();
  try {
    const res = await fetch(`${DS_API}/api/v0/chat/create_pow_challenge`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "authorization": `Bearer ${token}`,
        "x-app-version": "20241129.1",
        "x-client-platform": "web",
        "x-client-version": "1.8.0",
      },
      body: JSON.stringify({ target_path: targetPath }),
    });
    const data = await res.json() as any;
    const ch = data?.data?.biz_data?.challenge;
    if (!ch) {
      console.warn(`[ds-proxy] [pow] ⚠ no challenge in response for ${targetPath} (HTTP ${res.status})`);
      return null;
    }
    const { algorithm, challenge, salt, difficulty, expire_at, signature } = ch;
    const answer = solvePoW(challenge, salt, difficulty, expire_at);
    if (answer === null) {
      console.warn(`[ds-proxy] [pow] ⚠ WASM solver returned null for ${targetPath}`);
      return null;
    }
    console.log(`[ds-proxy] [pow] ✓ solved ${targetPath} in ${Date.now() - t0}ms (difficulty=${difficulty})`);
    return btoa(JSON.stringify({ algorithm, challenge, salt, answer, signature, target_path: targetPath }));
  } catch (e: any) {
    console.error(`[ds-proxy] [pow] ✗ threw for ${targetPath}: ${e.message}`);
    return null;
  }
}

// ─── Request headers ──────────────────────────────────────────────────────────
function dsHeaders(acc: PoolAccount, powResponse?: string | null): Record<string, string> {
  const h: Record<string, string> = {
    "authorization": `Bearer ${acc.token}`,
    "content-type": "application/json",
    "x-app-version": "20241129.1",
    "x-client-platform": "web",
    "x-client-version": "1.8.0",
    "x-client-locale": "en_US",
    "x-client-timezone-offset": "36000",
    "referer": "https://chat.deepseek.com/",
    "origin": "https://chat.deepseek.com",
    "user-agent": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Mobile Safari/537.36",
  };
  if (acc.dliq) h["x-hif-dliq"] = acc.dliq;
  if (acc.leim) h["x-hif-leim"] = acc.leim;
  if (powResponse) h["x-ds-pow-response"] = powResponse;
  return h;
}

// ─── Context offload threshold ───────────────────────────────────────────────
// When the estimated prompt exceeds this, serialize history to a file and
// upload to DeepSeek's file API. Removes the lost-in-the-middle problem by
// converting old context from inline tokens into a document the model reads.
const CONTEXT_OFFLOAD_CHARS = 60_000;
/** Formatting overhead added by openAIToDS (output integrity guard, DSML block, echo-step, labels) */
const PROMPT_OVERHEAD_CHARS = 8_000;

// ─── History transcript builder ───────────────────────────────────────────────
// Mirrors ds2api's BuildOpenAICurrentInputContextTranscript format exactly.
function buildHistoryTranscript(messages: any[]): string {
  const lines: string[] = [
    "# DS2API_HISTORY.txt",
    "Prior conversation history and tool progress.",
    "",
  ];
  let n = 0;
  for (const msg of messages) {
    const text = typeof msg.content === "string"
      ? msg.content
      : Array.isArray(msg.content)
        ? msg.content.map((b: any) => b.text || "").join("")
        : "";
    const hasToolCalls = (msg.tool_calls?.length ?? 0) > 0;
    if (!text && !hasToolCalls) continue;
    n++;
    const role = (msg.role || "user").toUpperCase().replace("FUNCTION", "TOOL");
    lines.push(`=== ${n}. ${role} ===`);
    if (msg.role === "tool") {
      const toolCallId = (msg as any).tool_call_id || "";
      const toolName = (msg as any).name || "";
      lines.push(`[name=${toolName} tool_call_id=${toolCallId}]`);
    }
    if (hasToolCalls) {
      for (const tc of msg.tool_calls) {
        const name = tc.function?.name || tc.name || "unknown";
        const argsStr = typeof tc.function?.arguments === "string"
          ? tc.function.arguments
          : JSON.stringify(tc.function?.arguments ?? (tc as any).input ?? {});
        lines.push(`[tool_call: ${name}(${argsStr})]`);
      }
    }
    if (text) lines.push(text);
    lines.push("");
  }
  return lines.join("\n").trimEnd() + "\n";
}

// ─── DeepSeek file upload + poll ─────────────────────────────────────────────
const FILE_READY_STATUSES = new Set(["processed","ready","done","available","success","completed","finished"]);

async function uploadHistoryFile(
  acc: PoolAccount,
  transcript: string,
  modelType: string,
  rid: string
): Promise<string | null> {
  const pow = await getPowResponse("/api/v0/file/upload_file", acc.token);
  if (!pow) {
    console.warn(`[ds-proxy] [${rid}] [file-upload] ⚠ PoW failed — skipping file offload`);
    return null;
  }

  const fileBytes = new TextEncoder().encode(transcript);
  const boundary = `----FormBoundary${Date.now().toString(36)}${Math.random().toString(36).slice(2)}`;
  const enc2 = new TextEncoder();
  const headerPart = enc2.encode(
    `--${boundary}\r\n` +
    `Content-Disposition: form-data; name="file"; filename="DS2API_HISTORY.txt"\r\n` +
    `Content-Type: text/plain; charset=utf-8\r\n\r\n`
  );
  const footerPart = enc2.encode(`\r\n--${boundary}--\r\n`);
  const bodyBuf = new Uint8Array(headerPart.length + fileBytes.length + footerPart.length);
  bodyBuf.set(headerPart, 0);
  bodyBuf.set(fileBytes, headerPart.length);
  bodyBuf.set(footerPart, headerPart.length + fileBytes.length);

  const t0 = Date.now();
  console.log(`[ds-proxy] [${rid}] [file-upload] uploading ${transcript.length} char history (${fileBytes.length} bytes)`);
  try {
    const res = await fetch(`${DS_API}/api/v0/file/upload_file`, {
      method: "POST",
      headers: {
        "authorization": `Bearer ${acc.token}`,
        "content-type": `multipart/form-data; boundary=${boundary}`,
        "x-app-version": "20241129.1",
        "x-client-platform": "web",
        "x-client-version": "1.8.0",
        "x-model-type": modelType,
        "x-ds-pow-response": pow,
        "x-file-size": String(fileBytes.length),
        "x-thinking-enabled": "1",
        "referer": "https://chat.deepseek.com/",
        "origin": "https://chat.deepseek.com",
        "user-agent": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Mobile Safari/537.36",
      },
      body: bodyBuf,
    });
    const data = await res.json() as any;
    const fileId: string | undefined =
      data?.data?.biz_data?.file?.id ||
      data?.data?.biz_data?.id ||
      data?.data?.file?.id ||
      data?.file_id;

    if (!fileId) {
      console.warn(`[ds-proxy] [${rid}] [file-upload] ⚠ no file ID — HTTP ${res.status}: ${JSON.stringify(data).slice(0, 300)}`);
      return null;
    }
    console.log(`[ds-proxy] [${rid}] [file-upload] ✓ uploaded fileId=${fileId} (${Date.now() - t0}ms) — polling for ready`);

    // Poll until the file is processed (max 30s)
    for (let i = 0; i < 30; i++) {
      await new Promise(r => setTimeout(r, 1000));
      try {
        const pollRes = await fetch(`${DS_API}/api/v0/file/fetch_files?file_ids=${fileId}`, {
          headers: {
            "authorization": `Bearer ${acc.token}`,
            "x-app-version": "20241129.1",
            "x-client-platform": "web",
            "x-client-version": "1.8.0",
          },
        });
        const pollData = await pollRes.json() as any;
        const files: any[] =
          pollData?.data?.biz_data?.files ||
          pollData?.data?.files ||
          [];
        const file = files.find((f: any) => f.id === fileId || f.file_id === fileId);
        const status = (file?.status || "").toLowerCase();
        if (FILE_READY_STATUSES.has(status)) {
          console.log(`[ds-proxy] [${rid}] [file-upload] ✓ ready (status=${status}) in ${Date.now() - t0}ms`);
          return fileId;
        }
        if (i % 5 === 0) console.log(`[ds-proxy] [${rid}] [file-upload] polling... status=${status || "unknown"} (${i + 1}/30)`);
      } catch (pe: any) {
        console.warn(`[ds-proxy] [${rid}] [file-upload] poll error: ${pe.message}`);
      }
    }
    console.warn(`[ds-proxy] [${rid}] [file-upload] ⚠ not ready after 30s — falling back to inline`);
    return null;
  } catch (e: any) {
    console.error(`[ds-proxy] [${rid}] [file-upload] ✗ upload threw: ${e.message}`);
    return null;
  }
}

// ─── V4 auto-continue ─────────────────────────────────────────────────────────
// DeepSeek V4 signals INCOMPLETE when a response is cut short. We call
// /api/v0/chat/continue to resume — up to 8 rounds (ds2api defaultAutoContinueLimit).
async function autoContinue(
  acc: PoolAccount,
  sessionId: string,
  messageId: number,
  pow: string | null,
  rid: string
): Promise<string> {
  console.log(`[ds-proxy] [${rid}] [v4-continue] calling /api/v0/chat/continue (msgId=${messageId})`);
  try {
    const res = await fetch(`${DS_API}/api/v0/chat/continue`, {
      method: "POST",
      headers: dsHeaders(acc, pow),
      body: JSON.stringify({
        chat_session_id: sessionId,
        message_id: messageId,
        fallback_to_resume: true,
      }),
    });
    let continuedText = "";
    const reader = res.body!.getReader();
    const decoder = new TextDecoder();
    let buf = "";
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const lines = buf.split("\n");
        buf = lines.pop() || "";
        for (const line of lines) {
          if (!line.startsWith("data:")) continue;
          const data = line.slice(5).trim();
          try {
            const event = JSON.parse(data);
            if (event.v && typeof event.v === "string") continuedText += event.v;
            else if (event.v?.content && typeof event.v.content === "string") continuedText += event.v.content;
          } catch { /* skip */ }
        }
      }
    } finally {
      reader.cancel();
    }
    console.log(`[ds-proxy] [${rid}] [v4-continue] ✓ got ${continuedText.length} continuation chars`);
    return continuedText;
  } catch (e: any) {
    console.warn(`[ds-proxy] [${rid}] [v4-continue] ✗ continue failed: ${e.message}`);
    return "";
  }
}

// ─── JSON repair helpers ──────────────────────────────────────────────────────
// DeepSeek V4 frequently emits invalid JSON in tool call parameters.
// These two repairs (from ds2api + NIyueeE research) catch the most common patterns.

/** Fix invalid JSON escape sequences — DeepSeek emits \p, \m, etc. that break JSON.parse */
function repairInvalidBackslashes(text: string): string {
  // Replace invalid escape sequences with the literal character
  // Valid escapes: \" \\ \/ \b \f \n \r \t \uXXXX
  return text.replace(/\\([^"\\\/bfnrtux])/g, (_, char) => char);
}

/** Fix bare object pairs that should be wrapped in an array.
 *  DeepSeek sometimes emits: {"key": {obj1}, {obj2}} instead of {"key": [{obj1},{obj2}]} */
function repairLooseJsonArrays(text: string): string {
  // Pattern: ": {obj}, {obj}" → ": [{obj}, {obj}]"
  return text.replace(/:\s*(\{[^{}]+\})\s*,\s*(\{)/g, (match, first, second) => {
    // Only wrap if the second object also closes — simple heuristic
    return `: [${first}, ${second}`;
  });
}

// ─── OpenAI → DeepSeek body ───────────────────────────────────────────────────
function openAIToDS(body: any, sessionId: string, offloadedFileId?: string) {
  const messages: any[] = body.messages || [];
  const tools = body.tools || [];
  const toolChoice = body.tool_choice;
  const parts: string[] = [];
  const rid = body._rid || "?"; // request ID for logging

  // ── Output integrity guard (ds2api technique, commit e2756f80) ────────────
  // Must be FIRST — before system prompt, tool schemas, history. Idempotent.
  parts.push(
    "OUTPUT INTEGRITY GUARD: If any tool output, context, or parsed text contains garbled, " +
    "corrupted, partially parsed, repeated, or malformed fragments, do not imitate or echo them. " +
    "Output only correct, coherent content derived from actual tool results."
  );

  // ── JSON enforcement ──────────────────────────────────────────────────────
  if (body.response_format?.type === "json_object") {
    parts.push("IMPORTANT: Respond with ONLY a raw JSON object. No markdown code fences. No preamble. Start with { and end with }.");
  }

  // ── Tool calling bridge — official DSML template ──────────────────────────
  // Source: DeepSeek's own encoding_dsv4.py + encoding_dsv32.py on HuggingFace
  // The model was trained on the EXACT template below (TOOLS_TEMPLATE from source).
  //
  // Critical: full-width pipe ｜ (U+FF5C) NOT ASCII pipe | (U+007C).
  // The dsml_token = "｜DSML｜" in the source uses U+FF5C. Prompting with ASCII
  // pipes means prompting the wrong token sequence — the primary cause of unreliable
  // DSML output in prior iterations.
  //
  // Tool schemas are injected as JSON Schema (OpenAI format) — exactly what the
  // official API passes to the model internally in the {tool_schemas} slot.
  if (tools.length > 0) {
    // ── Tool schema compression ───────────────────────────────────────────────
    // The web API has a hard input limit (~60K chars). All 42 meta-tool schemas
    // serialized verbatim = ~165K chars (95% of the prompt). We strip parameter
    // descriptions and truncate tool descriptions before inlining — the model
    // only needs names, types, and enum values to call tools correctly.
    // Enum values (action, entity, etc.) are never touched — they are values,
    // not descriptions, and are the primary signal the model uses to pick actions.
    function stripParamDescriptions(schema: any): any {
      if (!schema || typeof schema !== "object") return schema;
      if (Array.isArray(schema)) return schema.map(stripParamDescriptions);
      const out: any = {};
      for (const key of Object.keys(schema)) {
        if (key === "description") continue; // strip — model infers from param name
        out[key] = stripParamDescriptions(schema[key]);
      }
      return out;
    }

    // JSON Schema definitions — matches what the official DeepSeek API sends internally
    const toolSchemas = tools.map((t: any) => {
      const fn = t.function || t;
      const rawDesc: string = fn.description || "";
      const rawParams = fn.parameters || fn.input_schema || { type: "object", properties: {} };
      // Truncate description to first sentence or 150 chars, whichever is shorter
      const firstSentenceEnd = rawDesc.search(/[.!?](\s|$)/);
      const shortDesc = firstSentenceEnd > 0 && firstSentenceEnd < 150
        ? rawDesc.slice(0, firstSentenceEnd + 1)
        : rawDesc.slice(0, 150);
      return {
        name: fn.name || "unknown",
        description: shortDesc,
        parameters: stripParamDescriptions(rawParams),
      };
    });

    const rawToolChars = tools.reduce((s: number, t: any) => s + JSON.stringify(t).length, 0);
    const compressedToolChars = toolSchemas.reduce((s: number, t: any) => s + JSON.stringify(t).length, 0);
    console.log(`[ds-proxy] [${rid}] [openAIToDS] tool schema compression: ${rawToolChars} → ${compressedToolChars} chars (${Math.round((1 - compressedToolChars / rawToolChars) * 100)}% reduction)`);

    // tool_choice enforcement
    let choiceHint = "";
    if (toolChoice === "required" || toolChoice === "any") {
      choiceHint = "\n\nYou MUST call at least one tool.";
    } else if (typeof toolChoice === "object" && toolChoice?.function?.name) {
      choiceHint = `\n\nYou MUST call the tool "${toolChoice.function.name}".`;
    } else if (toolChoice === "none") {
      choiceHint = "\n\nDo NOT call any tools. Respond with plain text only.";
    }

    // Official TOOLS_TEMPLATE from encoding_dsv4.py — verbatim, with full-width ｜
    parts.push(
      `## Tools\n\n` +
      `You have access to a set of tools to help answer the user's question. ` +
      `You can invoke tools by writing a "<｜DSML｜tool_calls>" block like the following as part of your reply. ` +
      `You can use tools multiple times in a single reply.\n\n` +
      `<｜DSML｜tool_calls>\n` +
      `<｜DSML｜invoke name="$TOOL_NAME">\n` +
      `<｜DSML｜parameter name="$PARAMETER_NAME" string="true|false">$PARAMETER_VALUE</｜DSML｜parameter>\n` +
      `</｜DSML｜invoke>\n` +
      `</｜DSML｜tool_calls>\n\n` +
      `String parameters should be specified as is and set \`string="true"\`. ` +
      `For all other types (numbers, booleans, arrays, objects), pass the value in JSON format and set \`string="false"\`.\n\n` +
      `### Available Tool Schemas\n\n` +
      `${JSON.stringify(toolSchemas, null, 2)}\n\n` +
      `You MUST strictly follow the above defined tool name and parameter schemas to invoke tool calls.\n\n` +
      `After </｜DSML｜tool_calls> STOP immediately — no trailing text or explanation.\n\n` +
      `CRITICAL DATA RULES:\n` +
      `- ALWAYS call a tool to answer data questions (lists, counts, names, IDs, statuses). NEVER answer from memory or context.\n` +
      `- Tool results are AUTHORITATIVE. NEVER fabricate, invent, or substitute names, IDs, counts, or any values.\n` +
      `- If a tool returns N items, your response must reference exactly those N items verbatim.\n` +
      `- If you need data, call a tool — NEVER guess or hallucinate.` +
      `${choiceHint}`
    );

    console.log(`[ds-proxy] [${rid}] [openAIToDS] injected ${tools.length} tool schemas (official DSML template, full-width ｜), tool_choice=${typeof toolChoice === "object" ? JSON.stringify(toolChoice) : toolChoice || "auto"}`);
  }

  // ── Build conversation in official DeepSeek V4 format ─────────────────────
  // Source: encoding_dsv4.py from HuggingFace (read directly, May 2026).
  //
  // V4 special tokens used in the prompt:
  //   BOS:         <｜begin▁of▁sentence｜>            — first character of every prompt
  //   User turn:   <｜User｜>{content}<｜Assistant｜></think>   — user msg + asst prefix (chat mode)
  //   Asst turn:   {content}<｜end▁of▁sentence｜>              — response with EOS
  //   Tool call:   {text}\n\n<｜DSML｜tool_calls>...</｜DSML｜tool_calls><｜end▁of▁sentence｜>
  //   Tool result: <｜User｜><tool_result>{content}</tool_result><｜Assistant｜></think>
  //     • NO tool_call_id attribute — training format has none
  //     • Multiple results from same turn merged into ONE user block (V4 merge_tool_messages)
  //
  // Preamble (OUTPUT INTEGRITY GUARD, ## Tools) is joined before the conversation.

  // Role labels for conversation structure.
  // NOTE: V4 special tokens (<｜User｜>, <｜Assistant｜>, BOS, EOS) cause the DeepSeek
  // web API to return empty responses — the web endpoint blocks prompts containing
  // the model's own special tokens (treated as prompt injection). These plain-text
  // labels are understood by the model from pre-training data and work correctly
  // with the web API endpoint. DSML tool call tokens (<｜DSML｜invoke> etc.) are safe
  // because they only appear in the model's OUTPUT, not injected into the prompt context.
  const USER_TOKEN = "[USER]\n";
  const ASST_OPEN = "\n\n[ASSISTANT]\n";

  function extractText(msg: any): string {
    return typeof msg.content === "string"
      ? msg.content
      : Array.isArray(msg.content)
        ? msg.content.map((b: any) => b.text || "").join("")
        : "";
  }

  function buildDsmlCalls(toolCalls: any[]): string {
    // Source: encoding_dsv4.py tool_call_template + encode_arguments_to_dsml
    return toolCalls.map((tc: any) => {
      const name = tc.function?.name || tc.name || "unknown";
      let argsObj: Record<string, any> = {};
      try {
        argsObj = typeof tc.function?.arguments === "string"
          ? JSON.parse(tc.function.arguments)
          : tc.function?.arguments || tc.input || {};
      } catch { argsObj = {}; }
      const params = Object.entries(argsObj).map(([k, v]) => {
        const isStr = typeof v === "string";
        const val = isStr ? String(v) : JSON.stringify(v);
        // Full-width ｜ (U+FF5C) — exact p_dsml_template from encoding_dsv4.py
        return `<｜DSML｜parameter name="${k}" string="${isStr}">${val}</｜DSML｜parameter>`;
      }).join("\n");
      return `<｜DSML｜invoke name="${name}">\n${params}\n</｜DSML｜invoke>`;
    }).join("\n");
  }

  let systemCount = 0, assistantCount = 0, toolResultCount = 0, userCount = 0;

  // ── File-offload mode ─────────────────────────────────────────────────────
  if (offloadedFileId) {
    const preamble = parts.join("\n\n");
    const prompt =
      preamble + "\n\n" +
      "[USER]\n" +
      "Review the attached DS2API_HISTORY.txt which contains the conversation so far. " +
      "Answer the latest user request. If you need fresh data that is not already in the history, " +
      "call the appropriate tool — do not fabricate or guess values. " +
      "Never invent names, IDs, counts, or any other data.";
    userCount++;
    console.log(`[ds-proxy] [${rid}] [openAIToDS] file-offload mode — prompt=${prompt.length} chars (history in file ${offloadedFileId})`);
    return {
      chat_session_id: sessionId,
      parent_message_id: null,
      prompt,
      ref_file_ids: [offloadedFileId],
      thinking_enabled: !!body.thinking_enabled,
      search_enabled: !!body.search_enabled,
      model_type: body.model_type || "default",
    };
  }

  // ── System messages → preamble (no [SYSTEM] label, content only) ─────────
  for (const msg of messages) {
    if (msg.role === "system") {
      const text = extractText(msg);
      if (text) { parts.push(text); systemCount++; }
    }
  }

  // ── Conversation: non-system messages in V4 token format ─────────────────
  // Consecutive tool messages merged into ONE user block (V4 merge_tool_messages).
  let convStr = "";
  let maxToolResultLen = 0; // track longest result for echo-step threshold

  const nonSystem = messages.filter(m => m.role !== "system");
  let i = 0;
  while (i < nonSystem.length) {
    const msg = nonSystem[i];
    const text = extractText(msg);

    if (msg.role === "user") {
      parts.push(`[USER]\n${text}`);
      userCount++;
      i++;
    } else if (msg.role === "assistant") {
      const toolCalls = (msg as any).tool_calls;
      if (toolCalls?.length) {
        const dsmlCalls = buildDsmlCalls(toolCalls);
        parts.push(`[ASSISTANT]\n${text ? text + "\n\n" : ""}<｜DSML｜tool_calls>\n${dsmlCalls}\n</｜DSML｜tool_calls>`);
        assistantCount++;
      } else if (text) {
        parts.push(`[ASSISTANT]\n${text}`);
        assistantCount++;
      }
      i++;
    } else if (msg.role === "tool") {
      // Merge ALL consecutive tool messages into ONE user block.
      // V4 tool_output_template = "<tool_result>{content}</tool_result>" — no attributes.
      // Multiple results from same turn joined into one block (V4 merge_tool_messages).
      const resultBlocks: string[] = [];
      while (i < nonSystem.length && nonSystem[i].role === "tool") {
        const toolText = extractText(nonSystem[i]);
        resultBlocks.push(`<tool_result>\n${toolText}\n</tool_result>`);
        if (toolText.length > maxToolResultLen) maxToolResultLen = toolText.length;
        toolResultCount++;
        i++;
      }
      parts.push(`[USER]\n${resultBlocks.join("\n\n")}`);
    } else {
      // Unknown role: treat as user
      if (text) { parts.push(`[USER]\n${text}`); userCount++; }
      i++;
    }
  }

  // ── Echo-step grounding (only for substantial results >500 chars) ─────────
  // Moves tool data to high-recency position at end of prompt; adds count constraint.
  // Short results ({count:14}, {ok:true}) are excluded — overhead outweighs benefit.
  const hasSubstantialResult = toolResultCount > 0 && maxToolResultLen > 500;
  if (hasSubstantialResult) {
    parts.push(
      `[USER]\n` +
      `The tool returned the above data. Respond using this two-step approach:\n` +
      `Step 1: List every item exactly as it appears in the tool result — copy names, IDs, and values verbatim, changing nothing.\n` +
      `Step 2: Using only that list from Step 1, answer the original request naturally.\n\n` +
      `CONSTRAINTS:\n` +
      `- If the tool returned N items, your response must contain exactly N items — no more, no fewer.\n` +
      `- NEVER invent, substitute, or paraphrase any name, ID, count, price, or identifier.\n` +
      `- If you do not have the data, call a tool — never fabricate.`
    );
    userCount++;
  }

  const prompt = parts.join("\n\n");
  console.log(`[ds-proxy] [${rid}] [openAIToDS] prompt=${prompt.length} chars | system=${systemCount} assistant=${assistantCount} tool_results=${toolResultCount} user=${userCount} tools=${tools.length} echo_step=${hasSubstantialResult}`);

  return {
    chat_session_id: sessionId,
    parent_message_id: null,
    prompt,
    ref_file_ids: [],
    thinking_enabled: !!body.thinking_enabled,
    search_enabled: !!body.search_enabled,
    // model_type controls Chat (V3/V4-Flash, better tool calling) vs Expert (R1/V4-Pro, reasoning)
    // Default to "chat" — V3/Flash follows DSML format more reliably, no <think> blocks,
    // higher input tolerance. Use "expert" only when caller explicitly requests reasoning.
    model_type: body.model_type || "default",
  };
}

// ─── Tool call extraction from text output ───────────────────────────────────
// DeepSeek web API doesn't support native tool_calls. The model outputs tool
// invocations as text in various formats. We parse all known patterns and
// convert to structured tool calls.

interface ParsedToolCall { name: string; input: Record<string, any> }

/**
 * Normalize Unicode lookalike characters the model uses in place of the DSML
 * full-width pipe ｜ (U+FF5C). DeepSeek sometimes generates ︵ (U+FE35),
 * （ (U+FF08), or other curved/bracket variants, especially when routed to R1.
 * Normalizing before parsing makes all downstream regexes work without changes.
 */
function normalizeDsmlText(text: string): string {
  // Replace any character that appears between < and DSML or after DSML and before >
  // with the canonical full-width pipe ｜ (U+FF5C).
  // Common lookalikes observed: ︵ (FE35), ︶ (FE36), （ (FF08), ） (FF09), | (007C)
  return text
    .replace(/<[^\x00-\x7F｜]DSML[^\x00-\x7F｜]/g, (m) => "<｜DSML｜")
    .replace(/<\/[^\x00-\x7F｜]DSML[^\x00-\x7F｜]/g, "</｜DSML｜")
    // Also handle when the model omits pipes entirely: <DSMLinvoke → <｜DSML｜invoke
    .replace(/<DSML([a-z_])/gi, "<｜DSML｜$1")
    .replace(/<\/DSML([a-z_])/gi, "</｜DSML｜$1");
}

function extractToolCallsFromText(text: string, rid?: string): ParsedToolCall[] {
  const calls: ParsedToolCall[] = [];
  const tag = rid ? `[ds-proxy] [${rid}] [tool-parse]` : "[tool-parse]";

  // Normalize DSML lookalike characters before any regex runs
  const normalizedText = normalizeDsmlText(text);
  if (normalizedText !== text) {
    console.log(`${tag} [normalize] DSML character variants normalized (${text.length} chars)`);
  }
  text = normalizedText;

  // Anti-leak: strip content inside markdown code fences before parsing
  // (prevents matching tool-call examples in code blocks)
  const codeBlockRanges: Array<[number, number]> = [];
  const cbRegex = /```[\s\S]*?```/g;
  let cbMatch;
  while ((cbMatch = cbRegex.exec(text)) !== null) {
    codeBlockRanges.push([cbMatch.index, cbMatch.index + cbMatch[0].length]);
  }
  const isInCodeBlock = (pos: number) => codeBlockRanges.some(([s, e]) => pos >= s && pos < e);

  // Pattern 0 (HIGHEST PRIORITY): DSML format — DeepSeek's native trained format
  //
  // Version differences (from official HuggingFace encoding files):
  //   V4:   <｜DSML｜tool_calls>     ... <｜DSML｜invoke> ... <｜DSML｜parameter string="true|false">
  //   V3.2: <｜DSML｜function_calls> ... same invoke/param format
  //   Pre-DSML (R1/V3.1): <function_calls><invoke> without pipe characters (caught in P1)
  //
  // Parser matches both full-width ｜ (U+FF5C, trained format) and ASCII | (U+007C, fallback).
  // The `string` attribute is required in V3.2+ — parser handles both with and without it.
  // Outer block name (tool_calls vs function_calls) is ignored — we match invoke tags directly.
  const dsmlInvokeRegex = /<[｜|]?DSML[｜|]invoke\s+name="([^"]+)"[^>]*>([\s\S]*?)<\/[｜|]?DSML[｜|]invoke>/g;
  // Matches both V3.2+ format (with string attr) and any parameter without the attr
  const dsmlParamRegex = /<[｜|]?DSML[｜|]parameter\s+name="([^"]+)"(?:\s+string="(true|false)")?[^>]*>([\s\S]*?)<[\/]?[｜|]?DSML[｜|]parameter>/g;
  let m;
  while ((m = dsmlInvokeRegex.exec(text)) !== null) {
    if (isInCodeBlock(m.index)) { console.log(`${tag} P0 DSML match skipped (inside code block)`); continue; }
    const toolName = m[1];
    const paramsBlock = m[2];
    const params: Record<string, any> = {};
    let pm;
    dsmlParamRegex.lastIndex = 0;
    while ((pm = dsmlParamRegex.exec(paramsBlock)) !== null) {
      const paramName = pm[1];
      const stringAttr = pm[2]; // "true" | "false" | undefined (pre-DSML models omit it)
      let rawVal = pm[3].trim();
      // Strip CDATA wrapper if present — model may wrap special chars in CDATA
      rawVal = rawVal.replace(/^<!\[CDATA\[([\s\S]*?)\]\]>$/, "$1").trim();
      // Strip EOS token if leaked into parameter value
      rawVal = rawVal.replace(/<｜end▁of▁sentence｜>$/, "").trim();
      if (stringAttr === "true" || (stringAttr === undefined && !/^[\[{]/.test(rawVal))) {
        // string="true" explicitly, or no attr and value doesn't look like JSON
        params[paramName] = rawVal;
      } else {
        // string="false" (non-string) or value looks like JSON — parse it
        const repaired = repairLooseJsonArrays(repairInvalidBackslashes(rawVal));
        try { params[paramName] = JSON.parse(repaired); } catch { params[paramName] = rawVal; }
      }
    }
    calls.push({ name: toolName, input: params });
    console.log(`${tag} P0 match (DSML): ${toolName}(${JSON.stringify(params).slice(0, 150)})`);
  }

  // If DSML matched, skip other patterns — DSML is authoritative
  if (calls.length > 0) {
    console.log(`${tag} ✓ extracted ${calls.length} tool call(s) via DSML from ${text.length} chars`);
    return calls;
  }

  // Near-miss diagnostics — log what the model actually output when DSML didn't match
  if (text.length > 0) {
    const hasDSMLPipe = /<[｜|]?DSML[｜|]/i.test(text);
    const hasInvoke = /<invoke\s+name=/i.test(text);
    const hasFuncCalls = /<function_calls>/i.test(text);
    const hasToolCalls = /<tool_calls>/i.test(text);
    if (hasDSMLPipe || hasInvoke || hasFuncCalls || hasToolCalls) {
      console.warn(`${tag} ⚠ tool-call markers found but parser didn't match (DSML=${hasDSMLPipe} invoke=${hasInvoke} func_calls=${hasFuncCalls} tool_calls=${hasToolCalls}). Preview: "${text.slice(0, 400).replace(/\n/g, "\\n")}"`);
    }
  }

  // Pattern 1 (FALLBACK): Pre-DSML and V3.2 training-instability formats
  // Three sub-patterns in descending specificity:
  //   P1a: <function_calls><invoke name="..."> (V3.2 without DSML pipes — confirmed instability)
  //   P1b: <tool_calls><invoke name="...">     (same but with tool_calls wrapper)
  //   P1c: bare <invoke name="...">            (no outer wrapper — model omitted block entirely)
  // All confirmed in: HuggingFace V3.2 discussions #29, sglang #14695, vLLM #30541
  const legacyInvokeRegex = /<invoke\s+name="([^"]+)"[^>]*>([\s\S]*?)<\/invoke>/g;
  const legacyParamRegex = /<parameter\s+name="([^"]+)"(?:\s+string="(true|false)")?[^>]*>([\s\S]*?)<\/parameter>/g;
  let lm;
  while ((lm = legacyInvokeRegex.exec(text)) !== null) {
    if (isInCodeBlock(lm.index)) continue;
    const toolName = lm[1];
    const paramsBlock = lm[2];
    const params: Record<string, any> = {};
    let pm2;
    legacyParamRegex.lastIndex = 0;
    while ((pm2 = legacyParamRegex.exec(paramsBlock)) !== null) {
      const k = pm2[1];
      const stringAttr = pm2[2]; // may be present in V3.2 fallback output
      let v = pm2[3].trim().replace(/^<!\[CDATA\[([\s\S]*?)\]\]>$/, "$1").trim();
      if (stringAttr === "true" || (stringAttr === undefined && !/^[\[{]/.test(v))) {
        params[k] = v;
      } else {
        const repaired = repairLooseJsonArrays(repairInvalidBackslashes(v));
        try { params[k] = JSON.parse(repaired); } catch { params[k] = v; }
      }
    }
    calls.push({ name: toolName, input: params });
    console.log(`${tag} P1 match (legacy XML): ${toolName}(${JSON.stringify(params).slice(0, 150)})`);
  }

  if (calls.length > 0) {
    console.log(`${tag} ✓ extracted ${calls.length} tool call(s) via legacy XML from ${text.length} chars`);
    return calls;
  }

  // Pattern 2 (LAST RESORT): Bare JSON object — model emits {"name":"tool","arguments":{...}}
  // The regex anchors on the opening brace of the arguments object, then a balanced-brace walk
  // finds the real closing brace — fixing the non-greedy `}` problem with nested arguments.
  const bareJsonRegex = /\{\s*"name"\s*:\s*"([^"]+)"\s*,\s*"arguments"\s*:\s*(\{)/g;
  let bm;
  while ((bm = bareJsonRegex.exec(text)) !== null) {
    if (isInCodeBlock(bm.index)) continue;
    const toolName = bm[1];
    // Walk forward from the opening '{' of arguments to find the balanced closing '}'
    const argsStart = bm.index + bm[0].length - 1; // position of the '{' captured in group 2
    let depth = 0;
    let argsEnd = -1;
    let inStr = false;
    let escNext = false;
    for (let i = argsStart; i < text.length; i++) {
      const ch = text[i];
      if (escNext) { escNext = false; continue; }
      if (ch === "\\" && inStr) { escNext = true; continue; }
      if (ch === '"') { inStr = !inStr; continue; }
      if (inStr) continue;
      if (ch === "{") depth++;
      else if (ch === "}") { depth--; if (depth === 0) { argsEnd = i; break; } }
    }
    const argsStr = argsEnd > -1 ? text.slice(argsStart, argsEnd + 1) : bm[2];
    try {
      const repaired = repairLooseJsonArrays(repairInvalidBackslashes(argsStr));
      const args = JSON.parse(repaired);
      calls.push({ name: toolName, input: args });
      console.log(`${tag} P2 match (bare JSON): ${toolName}(${JSON.stringify(args).slice(0, 150)})`);
    } catch { /* skip malformed */ }
  }

  if (calls.length > 0) {
    console.log(`${tag} ✓ extracted ${calls.length} tool call(s) via bare JSON from ${text.length} chars`);
  }

  return calls;
}

function stripToolCallText(text: string): string {
  text = normalizeDsmlText(text);
  return text
    // DSML V4: <｜DSML｜tool_calls>...</｜DSML｜tool_calls> (full-width or ASCII pipe)
    .replace(/<[｜|]?DSML[｜|]tool_calls>[\s\S]*?<\/[｜|]?DSML[｜|]tool_calls>/g, "")
    // DSML V3.2: <｜DSML｜function_calls>...</｜DSML｜function_calls>
    .replace(/<[｜|]?DSML[｜|]function_calls>[\s\S]*?<\/[｜|]?DSML[｜|]function_calls>/g, "")
    // Orphaned DSML invoke blocks (outer wrapper stripped or missing)
    .replace(/<[｜|]?DSML[｜|]invoke[\s\S]*?<\/[｜|]?DSML[｜|]invoke>/g, "")
    // Pre-DSML legacy: <function_calls>...</function_calls>
    .replace(/<function_calls>[\s\S]*?<\/function_calls>/g, "")
    // Legacy: <tool_calls>...</tool_calls>
    .replace(/<tool_calls>[\s\S]*?<\/tool_calls>/g, "")
    // Bare <invoke> without wrapper
    .replace(/<invoke[\s\S]*?<\/invoke>/g, "")
    // EOS token that leaked into text
    .replace(/<｜end▁of▁sentence｜>/g, "")
    // Bare JSON tool call pattern
    .replace(/\{\s*"name"\s*:\s*"[^"]+"\s*,\s*"arguments"\s*:\s*\{[\s\S]*?\}\s*\}/g, "")
    .trim();
}

// ─── Check for expired-token error code ──────────────────────────────────────
async function isExpiredToken(res: Response): Promise<{ expired: boolean; text: string }> {
  const text = await res.text();
  try {
    const j = JSON.parse(text) as any;
    const code = j?.code ?? j?.error?.code ?? j?.data?.code;
    if (code === 40003 || code === "40003") return { expired: true, text };
  } catch { /* not JSON */ }
  if (text.includes("40003")) return { expired: true, text };
  return { expired: false, text };
}

// ─── Core completion (one attempt with a given account) ───────────────────────
async function doCompletion(body: any, acc: PoolAccount, rid: string) {
  console.log(`[ds-proxy] [completion] [${rid}] creating session for ${acc.email || "??"}`);
  const t0 = Date.now();
  const sessionRes = await fetch(`${DS_API}/api/v0/chat_session/create`, {
    method: "POST",
    headers: dsHeaders(acc),
    body: JSON.stringify({ agent: "chat", character_id: null }),
  });
  const sessionData = await sessionRes.json() as any;
  const sessionId = sessionData?.data?.biz_data?.chat_session?.id;
  if (!sessionId) {
    console.error(`[ds-proxy] [completion] [${rid}] ✗ session create failed HTTP ${sessionRes.status}: ${JSON.stringify(sessionData).slice(0, 200)}`);
    throw new Error(`Session create failed: ${JSON.stringify(sessionData).slice(0, 200)}`);
  }
  console.log(`[ds-proxy] [completion] [${rid}] session=${sessionId} (${Date.now() - t0}ms)`);

  // ── Context offload check ────────────────────────────────────────────────
  // Estimate the inline prompt size. If it would exceed the threshold, upload
  // the conversation history as a file — this removes the lost-in-the-middle
  // problem by converting buried context into a document DeepSeek reads cleanly.
  let offloadedFileId: string | undefined;
  const messages: any[] = body.messages || [];
  const tools: any[] = body.tools || [];
  const modelType: string = body.model_type || "default";

  if (tools.length > 0 && messages.length > 2) {
    // Estimate conversation history size only — tool schemas are in the preamble and
    // always visible to the model regardless of context length, so counting them here
    // would cause every request with many tools (42 in MAI) to hit the offload threshold
    // even on the very first message, defeating the purpose of the threshold entirely.
    // Context offload is for LONG CONVERSATION history (tool results, prior turns),
    // not for the fixed preamble overhead.
    const msgChars = messages.reduce((sum, m) => {
      const text = typeof m.content === "string" ? m.content.length
        : Array.isArray(m.content) ? m.content.reduce((s: number, b: any) => s + (b.text?.length || 0), 0)
        : 0;
      return sum + text;
    }, 0);
    const estimatedSize = msgChars + PROMPT_OVERHEAD_CHARS;

    if (estimatedSize > CONTEXT_OFFLOAD_CHARS) {
      console.log(`[ds-proxy] [${rid}] [context-offload] estimated ${estimatedSize} chars > ${CONTEXT_OFFLOAD_CHARS} threshold — uploading history`);
      const transcript = buildHistoryTranscript(messages);
      offloadedFileId = await uploadHistoryFile(acc, transcript, modelType, rid) || undefined;
      if (offloadedFileId) {
        console.log(`[ds-proxy] [${rid}] [context-offload] ✓ history offloaded to ${offloadedFileId} — inline prompt will be minimal`);
      } else {
        console.warn(`[ds-proxy] [${rid}] [context-offload] ⚠ upload failed — falling back to inline (hallucination risk at ${estimatedSize} chars)`);
      }
    }
  }

  const pow = await getPowResponse("/api/v0/chat/completion", acc.token);
  console.log(`[ds-proxy] [completion] [${rid}] PoW=${pow ? "solved" : "skipped"} — calling /chat/completion`);

  const upstream = await fetch(`${DS_API}/api/v0/chat/completion`, {
    method: "POST",
    headers: dsHeaders(acc, pow),
    body: JSON.stringify(openAIToDS({ ...body, _rid: rid }, sessionId, offloadedFileId)),
  });
  console.log(`[ds-proxy] [completion] [${rid}] upstream HTTP ${upstream.status} (${Date.now() - t0}ms total)`);

  return { upstream, sessionId, pow };
}

// ─── Notify SmartAssist when pool is exhausted ────────────────────────────────
let lastExhaustedNotify = 0;

function notifyPoolExhausted() {
  const now = Date.now();
  if (now - lastExhaustedNotify < 5 * 60 * 1000) {
    console.log("[ds-proxy] [exhausted] debounce active — skipping notify");
    return;
  }
  lastExhaustedNotify = now;

  const saUrl = process.env.SMARTASSIST_URL || "";
  const internalTok = process.env.INTERNAL_AUTH_TOKEN || "";
  if (!saUrl) {
    console.warn("[ds-proxy] [exhausted] SMARTASSIST_URL not set — cannot notify");
    return;
  }

  const stats = poolSummary();
  console.log(`[ds-proxy] [exhausted] 🚨 pool exhausted — notifying SmartAssist (total=${stats.total} active=${stats.active} cooling=${stats.cooling} dead=${stats.dead})`);

  getSmartAssistIdToken().then(idToken => {
    fetch(`${saUrl}/api/webhooks/deepseek-proxy`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(internalTok ? { "x-internal-token": internalTok } : {}),
        ...(idToken ? { "Authorization": `Bearer ${idToken}` } : {}),
      },
      body: JSON.stringify({ reason: "pool_exhausted", pool: stats }),
    })
      .then(r => console.log(`[ds-proxy] [exhausted] SmartAssist notified HTTP ${r.status}`))
      .catch(e => console.error(`[ds-proxy] [exhausted] ✗ notify failed: ${e.message}`));
  });
}

// ─── Admin auth ───────────────────────────────────────────────────────────────
function isAdmin(req: Request): boolean {
  if (!INTERNAL_TOKEN) return true;
  const h = req.headers.get("x-internal-token") || req.headers.get("authorization") || "";
  return h === INTERNAL_TOKEN || h === `Bearer ${INTERNAL_TOKEN}`;
}

// ─── Server ───────────────────────────────────────────────────────────────────
Bun.serve({
  port: PORT,
  idleTimeout: 255,

  async fetch(req) {
    const url = new URL(req.url);
    const rid = reqId();
    const t0 = Date.now();
    console.log(`[ds-proxy] [${rid}] → ${req.method} ${url.pathname}`);

    // ── Health ────────────────────────────────────────────────────────────────
    if (url.pathname === "/health") {
      const s = poolSummary();
      console.log(`[ds-proxy] [${rid}] health — total=${s.total} active=${s.active} cooling=${s.cooling} dead=${s.dead}`);
      return Response.json({ ok: true, port: PORT, pool: s });
    }

    // ── Admin: reload entire pool ─────────────────────────────────────────────
    if (url.pathname === "/admin/reload-pool" && req.method === "POST") {
      if (!isAdmin(req)) {
        console.warn(`[ds-proxy] [${rid}] reload-pool — unauthorized`);
        return Response.json({ error: "Unauthorized" }, { status: 401 });
      }
      const body = await req.json() as any;
      const accounts: PoolAccount[] = (body.accounts || []).map((a: any) => ({
        token: a.token || "",
        email: a.email,
        password: a.password,
        dliq: a.dliq || a.hif_dliq,
        leim: a.leim || a.hif_leim,
        status: a.token ? "active" : "cooling",
        failureCount: 0,
        lastUsed: 0,
        recentRequests: [],
        consecutiveEmpties: 0,
        totalWithContent: 0,
        totalEmpty: 0,
      }));
      if (!accounts.length) return Response.json({ error: "accounts array required" }, { status: 400 });
      const prev = poolSummary();
      pool = accounts;
      const next = poolSummary();
      console.log(`[ds-proxy] [${rid}] 🔄 pool reloaded — before: total=${prev.total} active=${prev.active} | after: total=${next.total} active=${next.active}`);
      pool.forEach(a => console.log(`[ds-proxy] [${rid}]   • ${a.email || "unknown"} | status=${a.status} | hasToken=${!!a.token} | hasDliq=${!!a.dliq}`));
      return Response.json({ ok: true, total: next.total, active: next.active });
    }

    // ── Admin: hot-swap single token (legacy compat) ──────────────────────────
    if (url.pathname === "/admin/reload-tokens" && req.method === "POST") {
      if (!isAdmin(req)) {
        console.warn(`[ds-proxy] [${rid}] reload-tokens — unauthorized`);
        return Response.json({ error: "Unauthorized" }, { status: 401 });
      }
      const body = await req.json() as any;
      if (!body.token) return Response.json({ error: "token required" }, { status: 400 });

      const existing = pool.find(a => a.email === body.email);
      if (existing) {
        existing.token = body.token;
        existing.status = "active";
        existing.failureCount = 0;
        existing.coolingUntil = undefined;
        existing.tokenObtainedAt = Date.now();
        existing.consecutiveEmpties = 0;
        existing.totalWithContent = 0;
        existing.totalEmpty = 0;
        if (body.dliq || body.hifDliq) existing.dliq = body.dliq || body.hifDliq;
        if (body.leim || body.hifLeim) existing.leim = body.leim || body.hifLeim;
        console.log(`[ds-proxy] [${rid}] 🔄 token updated for existing account ${body.email || "unknown"}`);
      } else {
        pool.push({ token: body.token, email: body.email, dliq: body.dliq, leim: body.leim, status: "active", failureCount: 0, lastUsed: 0, recentRequests: [], tokenObtainedAt: Date.now(), consecutiveEmpties: 0, totalWithContent: 0, totalEmpty: 0 });
        console.log(`[ds-proxy] [${rid}] 🔄 new account added to pool: ${body.email || "unknown"} (pool size now ${pool.length})`);
      }
      return Response.json({ ok: true, poolSize: pool.length });
    }

    // ── Admin: trigger re-login for all cooling/dead accounts ─────────────────
    if (url.pathname === "/admin/relogin-all" && req.method === "POST") {
      if (!isAdmin(req)) {
        console.warn(`[ds-proxy] [${rid}] relogin-all — unauthorized`);
        return Response.json({ error: "Unauthorized" }, { status: 401 });
      }
      const targets = pool.filter(a => a.status !== "active" && a.email && a.password);
      console.log(`[ds-proxy] [${rid}] relogin-all — ${targets.length} account(s) to re-login: ${targets.map(a => a.email).join(", ")}`);
      targets.forEach(a => reloginAccount(a).catch(() => {}));
      return Response.json({ ok: true, relogging: targets.length, accounts: targets.map(a => a.email) });
    }

    // ── Pool status ───────────────────────────────────────────────────────────
    if (url.pathname === "/admin/pool-status" && req.method === "GET") {
      if (!isAdmin(req)) return Response.json({ error: "Unauthorized" }, { status: 401 });
      const medianTtlMs = tokenLifetimeObservations.length > 2
        ? tokenLifetimeObservations.slice().sort((a, b) => a - b)[Math.floor(tokenLifetimeObservations.length / 2)]
        : null;
      return Response.json({
        throttle: { windowMs: THROTTLE_WINDOW_MS, maxReq: THROTTLE_MAX_REQ },
        tokenLifetime: {
          observations: tokenLifetimeObservations.length,
          medianHours: medianTtlMs ? +(medianTtlMs / 3_600_000).toFixed(1) : null,
          lastExpiries: tokenLifetimeObservations.slice(-5).map(ms => +(ms / 3_600_000).toFixed(1) + "h"),
        },
        accounts: pool.map(a => ({
          email: a.email || "unknown",
          status: a.status,
          failureCount: a.failureCount,
          hasToken: !!a.token,
          hasCredentials: !!(a.email && a.password),
          tokenAgeHours: a.tokenObtainedAt ? +((Date.now() - a.tokenObtainedAt) / 3_600_000).toFixed(1) : null,
          lastUsed: a.lastUsed ? new Date(a.lastUsed).toISOString() : null,
          coolingUntil: a.coolingUntil ? new Date(a.coolingUntil).toISOString() : null,
          cooldownMin: a.coolingUntil ? +((a.coolingUntil - Date.now()) / 60_000).toFixed(1) : null,
          reqInWindow: windowCount(a),
          consecutiveEmpties: a.consecutiveEmpties,
          totalWithContent: a.totalWithContent,
          totalEmpty: a.totalEmpty,
          hitRate: a.totalWithContent + a.totalEmpty > 0
            ? +((a.totalWithContent / (a.totalWithContent + a.totalEmpty)) * 100).toFixed(1)
            : null,
        })),
      });
    }

    // ── Models ────────────────────────────────────────────────────────────────
    if (url.pathname === "/v1/models") {
      return Response.json({
        object: "list",
        data: [
          { id: "deepseek-chat",     object: "model", created: 1700000000, owned_by: "deepseek" },
          { id: "deepseek-reasoner", object: "model", created: 1700000000, owned_by: "deepseek" },
        ],
      });
    }

    // ── Anthropic Messages endpoint (for Claude Code compatibility) ────────
    // Accepts Anthropic /v1/messages format, converts to OpenAI, runs through
    // the DeepSeek completion pipeline, converts response back to Anthropic.
    // Auth: x-api-key header (Anthropic convention) or Authorization Bearer (GCP IAM)
    if (url.pathname === "/v1/messages" && req.method === "POST") {
      // Validate API key — accept x-api-key (Claude Code sends this), internal token, or GCP IAM
      const apiKey = req.headers.get("x-api-key") || "";
      const authHeader = req.headers.get("authorization") || "";
      const isGcpAuth = authHeader.startsWith("Bearer ey"); // GCP identity tokens start with ey
      if (!isGcpAuth && !isAdmin(req) && apiKey !== (process.env.DS_MESSAGES_API_KEY || process.env.INTERNAL_AUTH_TOKEN || "")) {
        return Response.json({ error: "Invalid API key" }, { status: 401 });
      }

      const anthropicBody = await req.json() as any;
      const isStream = !!anthropicBody.stream;
      console.log(`[ds-proxy] [${rid}] /v1/messages (Anthropic) model=${anthropicBody.model} stream=${isStream} msgs=${anthropicBody.messages?.length ?? 0}`);

      // ── Convert Anthropic request → OpenAI request ──
      const oaiMessages: any[] = [];

      // System message — force DeepSeek to separate reasoning from response using a delimiter
      if (anthropicBody.system) {
        const systemText = typeof anthropicBody.system === "string"
          ? anthropicBody.system
          : Array.isArray(anthropicBody.system)
            ? anthropicBody.system.map((b: any) => b.text || "").join("\n\n")
            : "";
        if (systemText) oaiMessages.push({ role: "system", content: systemText });
      }

      // Convert messages
      for (const msg of (anthropicBody.messages || [])) {
        if (msg.role === "user") {
          if (typeof msg.content === "string") {
            oaiMessages.push({ role: "user", content: msg.content });
          } else if (Array.isArray(msg.content)) {
            // Handle text blocks and tool_result blocks
            const textParts = msg.content.filter((b: any) => b.type === "text").map((b: any) => b.text).join("\n");
            const toolResults = msg.content.filter((b: any) => b.type === "tool_result");
            if (textParts) oaiMessages.push({ role: "user", content: textParts });
            for (const tr of toolResults) {
              oaiMessages.push({
                role: "tool",
                tool_call_id: tr.tool_use_id,
                content: typeof tr.content === "string" ? tr.content : JSON.stringify(tr.content),
              });
            }
          }
        } else if (msg.role === "assistant") {
          if (typeof msg.content === "string") {
            oaiMessages.push({ role: "assistant", content: msg.content });
          } else if (Array.isArray(msg.content)) {
            const textParts = msg.content.filter((b: any) => b.type === "text").map((b: any) => b.text).join("");
            const toolUses = msg.content.filter((b: any) => b.type === "tool_use");
            const assistantMsg: any = { role: "assistant", content: textParts || null };
            if (toolUses.length) {
              assistantMsg.tool_calls = toolUses.map((tu: any) => ({
                id: tu.id,
                type: "function",
                function: {
                  name: tu.name,
                  arguments: typeof tu.input === "string" ? tu.input : JSON.stringify(tu.input || {}),
                },
              }));
            }
            oaiMessages.push(assistantMsg);
          }
        }
      }

      // Convert Anthropic tools → OpenAI tools
      const oaiTools = (anthropicBody.tools || []).map((t: any) => ({
        type: "function",
        function: {
          name: t.name,
          description: t.description || "",
          parameters: t.input_schema || { type: "object", properties: {} },
        },
      }));

      // Convert tool_choice
      let oaiToolChoice: any = undefined;
      if (anthropicBody.tool_choice) {
        if (anthropicBody.tool_choice.type === "auto") oaiToolChoice = "auto";
        else if (anthropicBody.tool_choice.type === "none") oaiToolChoice = "none";
        else if (anthropicBody.tool_choice.type === "any") oaiToolChoice = "required";
        else if (anthropicBody.tool_choice.type === "tool") oaiToolChoice = { type: "function", function: { name: anthropicBody.tool_choice.name } };
      }

      // Build OpenAI-format body and process through existing pipeline
      const oaiBody = {
        model: "deepseek-chat",
        messages: oaiMessages,
        ...(oaiTools.length ? { tools: oaiTools, tool_choice: oaiToolChoice || "auto", _injectTools: true } : {}),
        max_tokens: anthropicBody.max_tokens || 4096,
        temperature: anthropicBody.temperature,
        stream: isStream,
        model_type: anthropicBody.thinking ? "expert" : "default",
        ...(anthropicBody.thinking ? { thinking_enabled: true } : {}),
      };

      // Route through the same completion pipeline as /v1/chat/completions
      const oaiResponse = await fetch(`http://localhost:${PORT}/v1/chat/completions`, {
        method: "POST",
        headers: { "content-type": "application/json", "authorization": req.headers.get("authorization") || "" },
        body: JSON.stringify(oaiBody),
      });

      if (!isStream) {
        // ── Non-streaming: convert OAI response → Anthropic response ──
        const oaiResult = await oaiResponse.json() as any;
        const choice = oaiResult.choices?.[0];
        if (!choice) return Response.json({ error: "No response from model" }, { status: 502 });

        const contentBlocks: any[] = [];
        let rawText = choice.message?.content || "";

        // Parse DSML tool calls from text output
        const textToolCalls = extractToolCallsFromText(rawText, rid);

        // Strip DSML and extract visible text
        const visibleText = stripToolCallText(rawText).trim();
        if (visibleText) contentBlocks.push({ type: "text", text: visibleText });

        for (const tc of textToolCalls) {
          contentBlocks.push({
            type: "tool_use",
            id: `toolu_${Math.random().toString(36).slice(2, 12)}`,
            name: tc.name,
            input: tc.input,
          });
        }

        // Also handle native OpenAI tool_calls if present
        if (choice.message?.tool_calls) {
          for (const tc of choice.message.tool_calls) {
            contentBlocks.push({
              type: "tool_use",
              id: tc.id || `toolu_${Math.random().toString(36).slice(2, 12)}`,
              name: tc.function.name,
              input: (() => { try { return JSON.parse(tc.function.arguments); } catch { return {}; } })(),
            });
          }
        }

        const hasToolUse = contentBlocks.some(b => b.type === "tool_use");
        const stopReason = hasToolUse ? "tool_use"
          : choice.finish_reason === "length" ? "max_tokens"
          : "end_turn";

        return Response.json({
          id: oaiResult.id || `msg_${Date.now()}`,
          type: "message",
          role: "assistant",
          model: anthropicBody.model || "deepseek-v4-pro",
          content: contentBlocks,
          stop_reason: stopReason,
          usage: {
            input_tokens: oaiResult.usage?.prompt_tokens || 0,
            output_tokens: oaiResult.usage?.completion_tokens || 0,
          },
        });
      }

      // ── Streaming: collect full response, then emit Anthropic events ──
      // DeepSeek web API doesn't support native tool calling, so tool calls
      // arrive as <tool_call>...</tool_call> text. We buffer the full response,
      // parse tool calls, then emit proper Anthropic content blocks.
      const te = new TextEncoder();

      // Collect the full streamed response first
      let fullText = "";
      const reader = oaiResponse.body!.getReader();
      const decoder = new TextDecoder();
      let sseBuffer = "";
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          sseBuffer += decoder.decode(value, { stream: true });
          const lines = sseBuffer.split("\n");
          sseBuffer = lines.pop() || "";
          for (const line of lines) {
            if (!line.startsWith("data:")) continue;
            const data = line.slice(5).trim();
            if (data === "[DONE]") continue;
            try {
              const chunk = JSON.parse(data);
              const content = chunk.choices?.[0]?.delta?.content;
              if (content) fullText += content;
            } catch { /* skip */ }
          }
        }
      } finally {
        reader.cancel();
      }

      // Parse DSML tool calls from collected text
      const parsedToolCalls = extractToolCallsFromText(fullText, rid);
      const textAfterToolStrip = stripToolCallText(fullText);
      const hasToolCalls = parsedToolCalls.length > 0;

      // Clean text for display
      const thinkingText = "";
      const cleanText = textAfterToolStrip;

      // Now emit Anthropic SSE events
      const stream = new ReadableStream({
        start(controller) {
          const emit = (event: string, data: any) => {
            controller.enqueue(te.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`));
          };

          const msgId = `msg_${Date.now()}`;
          emit("message_start", {
            type: "message_start",
            message: {
              id: msgId, type: "message", role: "assistant",
              model: anthropicBody.model || "deepseek-v4-pro",
              content: [], stop_reason: null,
              usage: { input_tokens: 0, output_tokens: 0 },
            },
          });

          let blockIndex = 0;

          // Emit thinking block (hidden in Claude Code by default)
          if (thinkingText) {
            emit("content_block_start", { type: "content_block_start", index: blockIndex, content_block: { type: "thinking", thinking: "" } });
            emit("content_block_delta", { type: "content_block_delta", index: blockIndex, delta: { type: "thinking_delta", thinking: thinkingText } });
            emit("content_block_stop", { type: "content_block_stop", index: blockIndex });
            blockIndex++;
          }

          // Emit text block (if any clean text exists)
          if (cleanText) {
            emit("content_block_start", { type: "content_block_start", index: blockIndex, content_block: { type: "text", text: "" } });
            emit("content_block_delta", { type: "content_block_delta", index: blockIndex, delta: { type: "text_delta", text: cleanText } });
            emit("content_block_stop", { type: "content_block_stop", index: blockIndex });
            blockIndex++;
          }

          // Emit tool_use blocks
          for (const tc of parsedToolCalls) {
            const toolId = `toolu_${Math.random().toString(36).slice(2, 12)}`;
            emit("content_block_start", {
              type: "content_block_start", index: blockIndex,
              content_block: { type: "tool_use", id: toolId, name: tc.name, input: {} },
            });
            emit("content_block_delta", {
              type: "content_block_delta", index: blockIndex,
              delta: { type: "input_json_delta", partial_json: JSON.stringify(tc.input) },
            });
            emit("content_block_stop", { type: "content_block_stop", index: blockIndex });
            blockIndex++;
          }

          // Message end
          const stopReason = hasToolCalls ? "tool_use" : "end_turn";
          emit("message_delta", { type: "message_delta", delta: { stop_reason: stopReason }, usage: { output_tokens: 0 } });
          emit("message_stop", { type: "message_stop" });

          controller.close();
        },
      });

      return new Response(stream, {
        headers: { "content-type": "text/event-stream", "cache-control": "no-cache" },
      });
    }

    // ── Chat completions ──────────────────────────────────────────────────────
    if (url.pathname === "/v1/chat/completions" && req.method === "POST") {
      const body = await req.json() as any;
      const isStream = !!body.stream;
      const msgCount = body.messages?.length ?? 0;
      const lastMsg = (body.messages?.[msgCount - 1]?.content ?? "").slice(0, 80);
      console.log(`[ds-proxy] [${rid}] chat/completions model=${body.model} stream=${isStream} messages=${msgCount} lastMsg="${lastMsg}…"`);

      const s = poolSummary();
      console.log(`[ds-proxy] [${rid}] pool state — active=${s.active} cooling=${s.cooling} dead=${s.dead} total=${s.total}`);

      let upstream: Response | null = null;
      let usedAcc: PoolAccount | null = null;
      let sessionId = "";
      let usedPow: string | null = null;
      let lastErrText = "";
      const tried = new Set<PoolAccount>();
      let attempt = 0;

      while (true) {
        attempt++;
        const acc = pickAccount();
        if (!acc || tried.has(acc)) {
          console.error(`[ds-proxy] [${rid}] ✗ all accounts exhausted after ${attempt - 1} attempt(s)`);
          notifyPoolExhausted();
          return Response.json({
            error: "All DeepSeek accounts exhausted — token refresh needed",
            pool: poolSummary(),
          }, { status: 503 });
        }

        tried.add(acc);
        acc.lastUsed = Date.now();
        recordRequest(acc);
        console.log(`[ds-proxy] [${rid}] attempt ${attempt} — using account ${acc.email || "??"} (reqInWindow=${windowCount(acc)})`);

        try {
          const result = await doCompletion(body, acc, rid);
          if (!result.upstream.ok) {
            const { expired, text } = await isExpiredToken(result.upstream);
            lastErrText = text;
            if (expired) {
              console.warn(`[ds-proxy] [${rid}] ⚠ 40003 (token expired) on ${acc.email || "??"} — expiring, trying next`);
              expireAccount(acc);
              continue;
            }
            if (result.upstream.status === 429) {
              console.warn(`[ds-proxy] [${rid}] ⚠ 429 (rate limit) on ${acc.email || "??"} — cooling, trying next`);
              coolAccount(acc); // progressive cooldown handles the timing
              continue;
            }
            console.error(`[ds-proxy] [${rid}] ✗ upstream HTTP ${result.upstream.status} on ${acc.email}: ${text.slice(0, 200)}`);
            return new Response(text, { status: result.upstream.status, headers: { "content-type": "application/json" } });
          }
          upstream = result.upstream;
          usedAcc = acc;
          sessionId = result.sessionId;
          usedPow = result.pow;
          break;
        } catch (err: any) {
          console.error(`[ds-proxy] [${rid}] ✗ doCompletion threw (${acc.email}): ${err.message}`);
          coolAccount(acc);
          continue;
        }
      }

      const setupMs = Date.now() - t0;
      console.log(`[ds-proxy] [${rid}] ✓ upstream ready — account=${usedAcc!.email || "??"} session=${sessionId} setupMs=${setupMs}`);

      // ── Streaming ────────────────────────────────────────────────────────
      // Buffer the full response, then check for tool calls before emitting.
      // If tool calls found, emit them as structured tool_calls instead of text.
      if (isStream) {
        const reader = upstream!.body!.getReader();
        const decoder = new TextDecoder();
        let sseBuffer = "";
        let fullText = "";
        let chunkCount = 0;

        // Collect full response — handles V4 continuation states (INCOMPLETE/auto_continue)
        // DeepSeek V4 can signal mid-stream that the response is incomplete and needs
        // a continuation request. Without this, responses silently truncate.
        let needsContinuation = false;
        let responseMessageId: number | null = null;
        // Raw SSE capture for empty-response diagnostics (kept until fullText > 0)
        const rawSseCapture: string[] = [];
        const MAX_RAW_CAPTURE = 30;
        try {
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            sseBuffer += decoder.decode(value, { stream: true });
            const lines = sseBuffer.split("\n");
            sseBuffer = lines.pop() || "";
            for (const line of lines) {
              // Capture raw lines for empty-response diagnostics
              if (rawSseCapture.length < MAX_RAW_CAPTURE && line.trim()) {
                rawSseCapture.push(line.slice(0, 400));
              }
              if (!line.trim() || line.startsWith("event:") || !line.startsWith("data:")) continue;
              const data = line.slice(5).trim();
              if (!data) continue;
              try {
                const event = JSON.parse(data);
                // V4 continuation state detection — auto_continue or INCOMPLETE signal
                if (event.auto_continue === true || event.finish_reason === "INCOMPLETE") {
                  console.log(`[ds-proxy] [${rid}] [v4-continue] continuation signal detected — will re-request`);
                  needsContinuation = true;
                }
                // Capture response message ID — needed for /api/v0/chat/continue call
                // DeepSeek may place the message ID in different fields depending on event type
                const mid = event.message_id ?? event.id ?? event.data?.message_id ?? event.response?.message_id;
                if (typeof mid === "number") responseMessageId = mid;
                else if (typeof mid === "string" && /^\d+$/.test(mid)) responseMessageId = parseInt(mid, 10);
                if (event.v && typeof event.v === "string") {
                  // Capture both bare text chunks AND APPEND events (which have event.p set)
                  fullText += event.v;
                  chunkCount++;
                } else if (typeof event.v === "object" && event.v !== null) {
                  // Check for fragment arrays (JSON Patch replace on response/fragments)
                  if (Array.isArray(event.v)) {
                    for (const frag of event.v) {
                      if (frag?.content) { fullText += frag.content; chunkCount++; }
                    }
                  } else if (event.v?.response?.fragments) {
                    for (const frag of event.v.response.fragments) {
                      if (frag.content) { fullText += frag.content; chunkCount++; }
                    }
                  } else if (event.v?.content && typeof event.v.content === "string") {
                    // Fragment object with content field directly
                    fullText += event.v.content;
                    chunkCount++;
                  } else if (chunkCount < 5) {
                    // Log first few unhandled object events for diagnostics
                    console.log(`[ds-proxy] [${rid}] [sse-diag] unhandled object event: ${JSON.stringify(event).slice(0, 300)}`);
                  }
                }
              } catch (parseErr: any) {
                // Log unparseable SSE data on empty responses
                if (chunkCount === 0 && rawSseCapture.length <= MAX_RAW_CAPTURE) {
                  console.log(`[ds-proxy] [${rid}] [sse-diag] JSON parse fail: ${data.slice(0, 200)}`);
                }
              }
            }
          }
        } finally {
          reader.cancel();
        }
        // Dump raw SSE events when response is empty — to diagnose API rejections
        if (fullText.length === 0 && rawSseCapture.length > 0) {
          console.log(`[ds-proxy] [${rid}] [sse-dump] EMPTY RESPONSE — raw SSE events (${rawSseCapture.length}):`);
          rawSseCapture.forEach((line, i) => console.log(`[ds-proxy] [${rid}] [sse-dump]   [${i}] ${line}`));
        }
        // V4 auto-continue loop — up to 8 rounds (mirrors ds2api defaultAutoContinueLimit)
        // When DeepSeek V4 signals INCOMPLETE, call /api/v0/chat/continue to resume.
        // PoW tokens are single-use — each round MUST get its own fresh token.
        // TODO: parse each continuation SSE for another INCOMPLETE signal to chain true multi-round.
        if (needsContinuation) {
          if (responseMessageId !== null) {
            console.log(`[ds-proxy] [${rid}] [v4-continue] response INCOMPLETE (${fullText.length} chars) — starting continuation loop (msgId=${responseMessageId})`);
            for (let round = 1; round <= 8; round++) {
              const roundPoW = await getPowResponse("/api/v0/chat/continue", usedAcc!.token);
              const continuation = await autoContinue(usedAcc!, sessionId, responseMessageId, roundPoW, rid);
              if (continuation.length > 0) {
                fullText += continuation;
                console.log(`[ds-proxy] [${rid}] [v4-continue] round ${round} — appended ${continuation.length} chars (total=${fullText.length})`);
                // autoContinue streams its own response; if it returns text, assume complete for now.
                // Future: parse continuation SSE for another INCOMPLETE signal to chain further rounds.
                break;
              } else {
                console.log(`[ds-proxy] [${rid}] [v4-continue] round ${round} — empty continuation, stopping`);
                break;
              }
            }
          } else {
            console.warn(`[ds-proxy] [${rid}] [v4-continue] ⚠ INCOMPLETE but no message_id in SSE events — returning partial (${fullText.length} chars)`);
          }
        }

        // Strip <think>...</think> blocks emitted by R1 (model_type: "expert")
        // The web API auto-routes complex queries to DeepSeek-R1 which prefixes
        // responses with chain-of-thought reasoning wrapped in <think> tags.
        // These are internal reasoning traces — not part of the answer.
        if (fullText.includes("<think>")) {
          const beforeStrip = fullText.length;
          fullText = fullText.replace(/<think>[\s\S]*?<\/think>\s*/g, "").trimStart();
          if (process.env.DEBUG || beforeStrip !== fullText.length) {
            console.log(`[ds-proxy] [${rid}] [r1-strip] stripped <think> block: ${beforeStrip} → ${fullText.length} chars`);
          }
        }

        const totalMs = Date.now() - t0;
        // Track empty responses
        if (fullText.length === 0) {
          usedAcc!.consecutiveEmpties++;
          usedAcc!.totalEmpty++;
          if (usedAcc!.consecutiveEmpties >= 3) {
            console.warn(`[ds-proxy] [${rid}] ⚠ ${usedAcc!.consecutiveEmpties} consecutive empty streams — proactive cooling ${usedAcc!.email || "??"}`);
            coolAccount(usedAcc!);
          }
        } else {
          usedAcc!.consecutiveEmpties = 0;
          usedAcc!.totalWithContent++;
          if (usedAcc!.totalWithContent % 5 === 0 && usedAcc!.failureCount > 0) {
            usedAcc!.failureCount = Math.max(0, usedAcc!.failureCount - 1);
          }
        }

        // Log response preview for debugging
        console.log(`[ds-proxy] [${rid}] [response] preview: "${fullText.slice(0, 200).replace(/\n/g, "\\n")}${fullText.length > 200 ? "..." : ""}"`);

        // Check for tool calls in the collected text
        const streamToolCalls = extractToolCallsFromText(fullText, rid);
        const msgId = `chatcmpl-ds-${Date.now()}`;
        const te = new TextEncoder();

        const stream = new ReadableStream({
          start(controller) {
            const emit = (chunk: any) => controller.enqueue(te.encode(`data: ${JSON.stringify(chunk)}\n\n`));

            if (streamToolCalls.length > 0) {
              // Emit clean text (if any) then tool calls
              const cleanContent = stripToolCallText(fullText).trim();
              console.log(`[ds-proxy] [${rid}] 🔧 stream: ${streamToolCalls.length} tool call(s) extracted, clean text=${cleanContent.length} chars`);

              if (cleanContent) {
                emit({ id: msgId, object: "chat.completion.chunk", created: Math.floor(Date.now() / 1000), model: body.model, choices: [{ index: 0, delta: { content: cleanContent }, finish_reason: null }] });
              }
              // Emit tool calls
              for (let i = 0; i < streamToolCalls.length; i++) {
                const tc = streamToolCalls[i];
                const callId = `call_${Date.now()}_${i}`;
                emit({ id: msgId, object: "chat.completion.chunk", created: Math.floor(Date.now() / 1000), model: body.model, choices: [{ index: 0, delta: { tool_calls: [{ index: i, id: callId, type: "function", function: { name: tc.name, arguments: JSON.stringify(tc.input) } }] }, finish_reason: null }] });
              }
              emit({ id: msgId, object: "chat.completion.chunk", created: Math.floor(Date.now() / 1000), model: body.model, choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }] });
            } else {
              // No tool calls — emit text as normal stream
              emit({ id: msgId, object: "chat.completion.chunk", created: Math.floor(Date.now() / 1000), model: body.model, choices: [{ index: 0, delta: { content: fullText }, finish_reason: null }] });
              emit({ id: msgId, object: "chat.completion.chunk", created: Math.floor(Date.now() / 1000), model: body.model, choices: [{ index: 0, delta: {}, finish_reason: "stop" }] });
            }
            controller.enqueue(te.encode("data: [DONE]\n\n"));
            controller.close();
          },
        });

        console.log(`[ds-proxy] [${rid}] ✓ stream done — account=${usedAcc!.email || "??"} chars=${fullText.length} chunks=${chunkCount} toolCalls=${streamToolCalls.length} totalMs=${totalMs}`);

        return new Response(stream, {
          headers: { "content-type": "text/event-stream", "cache-control": "no-cache", "connection": "keep-alive" },
        });
      }

      // ── Non-streaming ────────────────────────────────────────────────────
      const text = await upstream!.text();
      let fullText = "";
      for (const line of text.split("\n")) {
        if (!line.startsWith("data:")) continue;
        const data = line.slice(5).trim();
        try {
          const event = JSON.parse(data);
          if (event.v && typeof event.v === "string") fullText += event.v;
          else if (typeof event.v === "object" && event.v !== null) {
            if (Array.isArray(event.v)) {
              for (const f of event.v) if (f?.content) fullText += f.content;
            } else if (event.v?.response?.fragments) {
              for (const f of event.v.response.fragments) if (f.content) fullText += f.content;
            } else if (event.v?.content && typeof event.v.content === "string") {
              fullText += event.v.content;
            }
          }
        } catch { /* skip */ }
      }

      const totalMs = Date.now() - t0;
      // Track empty responses (chars=0) — early warning of DeepSeek throttling
      if (fullText.length === 0) {
        usedAcc!.consecutiveEmpties++;
        usedAcc!.totalEmpty++;
        // After 3 consecutive empties, proactively cool the account before hard block
        if (usedAcc!.consecutiveEmpties >= 3) {
          console.warn(`[ds-proxy] [${rid}] ⚠ ${usedAcc!.consecutiveEmpties} consecutive empty responses — proactive cooling ${usedAcc!.email || "??"}`);
          coolAccount(usedAcc!);
        }
      } else {
        usedAcc!.consecutiveEmpties = 0; // Reset on successful content
        usedAcc!.totalWithContent++;
        // Reset failure count on sustained success (5 good responses = trust restored)
        if (usedAcc!.totalWithContent % 5 === 0 && usedAcc!.failureCount > 0) {
          usedAcc!.failureCount = Math.max(0, usedAcc!.failureCount - 1);
        }
      }
      console.log(`[ds-proxy] [${rid}] ✓ non-stream done — account=${usedAcc!.email || "??"} chars=${fullText.length} totalMs=${totalMs}`);

      // ── Parse tool calls from text output for OpenAI format ──
      const parsedOAIToolCalls = extractToolCallsFromText(fullText, rid);
      if (parsedOAIToolCalls.length > 0) {
        const cleanContent = stripToolCallText(fullText).trim() || null;
        console.log(`[ds-proxy] [${rid}] 🔧 extracted ${parsedOAIToolCalls.length} tool call(s) from text — content=${cleanContent?.length ?? 0} chars`);
        return Response.json({
          id: `chatcmpl-ds-${Date.now()}`,
          object: "chat.completion",
          created: Math.floor(Date.now() / 1000),
          model: body.model,
          choices: [{ index: 0, message: {
            role: "assistant",
            content: cleanContent,
            tool_calls: parsedOAIToolCalls.map((tc, i) => ({
              id: `call_${Date.now()}_${i}`,
              type: "function",
              function: { name: tc.name, arguments: JSON.stringify(tc.input) },
            })),
          }, finish_reason: "tool_calls" }],
          usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
        });
      }

      return Response.json({
        id: `chatcmpl-ds-${Date.now()}`,
        object: "chat.completion",
        created: Math.floor(Date.now() / 1000),
        model: body.model,
        choices: [{ index: 0, message: { role: "assistant", content: fullText }, finish_reason: "stop" }],
        usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
      });
    }

    console.warn(`[ds-proxy] [${rid}] 404 — ${req.method} ${url.pathname}`);
    return Response.json({ error: "Not found" }, { status: 404 });
  },
});

const s = poolSummary();
console.log(`
╔══════════════════════════════════════════════════════╗
║       DeepSeek Web Proxy — Pool Mode                 ║
╠══════════════════════════════════════════════════════╣
║  Port:      ${PORT}
║  Base URL:  http://localhost:${PORT}/v1
║  Pool:      ${s.active}/${s.total} accounts active (${s.cooling} cooling, ${s.dead} dead)
║  VPS:       ${process.env.VPS_PROXY_URL || "not set — login calls go direct"}
║  Admin:     POST /admin/reload-pool   (full pool swap)
║             POST /admin/reload-tokens (single token)
║             GET  /admin/pool-status   (pool health)
║             POST /admin/relogin-all   (refresh cooled)
╚══════════════════════════════════════════════════════╝
`);
