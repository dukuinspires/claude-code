/**
 * ds-cache — DeepSeek Warm Cache Service for VPS
 *
 * Runs on VPS nodes (persistent state, 24/7 uptime) to pre-solve PoW
 * challenges and maintain a session pool. Cloud Run proxy calls these
 * endpoints to skip expensive on-demand creation (~700ms saved per request).
 *
 * Endpoints:
 *   GET  /health                        — service health
 *   GET  /pow?token=X&path=Y            — get pre-solved PoW (or solve on demand)
 *   GET  /session?token=X               — get pre-created session
 *   POST /session/release               — return session to pool (unused)
 *   POST /accounts                      — update account list for pre-solving
 *   GET  /stats                         — cache hit rates, pool sizes
 *
 * Auth: x-ds-cache-secret header (same as SMTP_PROXY_SECRET)
 */

import { readFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = parseInt(process.env.DS_CACHE_PORT || "3081", 10);
const SECRET = process.env.DS_CACHE_SECRET || process.env.SMTP_PROXY_SECRET || "";
const DS_API = "https://chat.deepseek.com";

// ─── WASM PoW Solver ─────────────────────────────────────────────────────────
const wasmPath = resolve(__dirname, "sha3_wasm_bg.wasm");
console.log(`[ds-cache] loading WASM from ${wasmPath}`);
const wasmBytes = readFileSync(wasmPath);
const { instance: wasmInstance } = await WebAssembly.instantiate(wasmBytes);
console.log(`[ds-cache] WASM loaded (${wasmBytes.length} bytes)`);

const {
  wasm_solve,
  __wbindgen_add_to_stack_pointer,
  __wbindgen_export_0: wasm_malloc,
  memory: wasmMemory,
} = wasmInstance.exports;

const enc = new TextEncoder();
let _wasmVecLen = 0;

function passStrToWasm(str) {
  const buf = enc.encode(str);
  const ptr = wasm_malloc(buf.length, 1);
  new Uint8Array(wasmMemory.buffer).set(buf, ptr);
  _wasmVecLen = buf.length;
  return ptr;
}

function solvePoW(challenge, salt, difficulty, expireAt) {
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

async function fetchAndSolvePoW(token, targetPath) {
  const t0 = Date.now();
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
  const data = await res.json();
  const ch = data?.data?.biz_data?.challenge;
  if (!ch) return null;

  const { algorithm, challenge, salt, difficulty, expire_at, signature } = ch;
  const answer = solvePoW(challenge, salt, difficulty, expire_at);
  if (answer === null) return null;

  const solved = btoa(JSON.stringify({ algorithm, challenge, salt, answer, signature, target_path: targetPath }));
  const ms = Date.now() - t0;
  return { solved, expireAt: expire_at, solvedAt: Date.now(), ms };
}

// ─── PoW Cache ───────────────────────────────────────────────────────────────
// Key: `${tokenHash}:${targetPath}` → { solved, expireAt, solvedAt }
const powCache = new Map();
const POW_SAFETY_MARGIN_MS = 10_000; // don't serve PoW within 10s of expiry

function powCacheKey(token, path) {
  // Use first 16 chars of token as key (enough to distinguish accounts)
  return `${token.slice(0, 16)}:${path}`;
}

function getCachedPow(token, path) {
  const key = powCacheKey(token, path);
  const entry = powCache.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expireAt - POW_SAFETY_MARGIN_MS) {
    powCache.delete(key);
    return null; // expired or about to
  }
  powCache.delete(key); // single-use
  return entry;
}

async function preSolvePow(token, path) {
  const key = powCacheKey(token, path);
  // Skip if already cached and not expiring soon
  const existing = powCache.get(key);
  if (existing && Date.now() < existing.expireAt - POW_SAFETY_MARGIN_MS * 2) return;

  try {
    const result = await fetchAndSolvePoW(token, path);
    if (result) {
      powCache.set(key, result);
      console.log(`[ds-cache] [pow] pre-solved ${path} in ${result.ms}ms (expires in ${Math.round((result.expireAt - Date.now()) / 1000)}s)`);
    }
  } catch (e) {
    console.warn(`[ds-cache] [pow] pre-solve failed for ${path}: ${e.message}`);
  }
}

// ─── Tool Schema File Upload ─────────────────────────────────────────────────
// Tool schemas are the same 42 tools on every request (43K chars compressed).
// Pre-upload them when creating each session so the proxy doesn't have to.
let cachedToolSchemas = null; // set via POST /tool-schemas

async function uploadToolSchemaFile(token, sessionId) {
  if (!cachedToolSchemas) return null;
  const t0 = Date.now();

  // Solve PoW for file upload
  const powResult = await fetchAndSolvePoW(token, "/api/v0/file/upload_file");
  if (!powResult) return null;

  const content = `# Tool Schemas\n\n${JSON.stringify(cachedToolSchemas, null, 2)}`;
  const fileBytes = new TextEncoder().encode(content);
  const boundary = `----FormBoundary${Date.now().toString(36)}${Math.random().toString(36).slice(2)}`;
  const headerPart = new TextEncoder().encode(
    `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="TOOL_SCHEMAS.json"\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n`
  );
  const footerPart = new TextEncoder().encode(`\r\n--${boundary}--\r\n`);
  const bodyBuf = new Uint8Array(headerPart.length + fileBytes.length + footerPart.length);
  bodyBuf.set(headerPart, 0);
  bodyBuf.set(fileBytes, headerPart.length);
  bodyBuf.set(footerPart, headerPart.length + fileBytes.length);

  const res = await fetch(`${DS_API}/api/v0/file/upload_file`, {
    method: "POST",
    headers: {
      "authorization": `Bearer ${token}`,
      "content-type": `multipart/form-data; boundary=${boundary}`,
      "x-app-version": "20241129.1",
      "x-client-platform": "web",
      "x-client-version": "1.8.0",
      "x-model-type": "default",
      "x-ds-pow-response": powResult.solved,
      "x-file-size": String(fileBytes.length),
      "x-thinking-enabled": "1",
      "referer": "https://chat.deepseek.com/",
      "origin": "https://chat.deepseek.com",
      "user-agent": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Mobile Safari/537.36",
    },
    body: bodyBuf,
  });
  const data = await res.json();
  const fileId = data?.data?.biz_data?.file?.id || data?.data?.biz_data?.id || data?.data?.file?.id || data?.file_id;
  if (!fileId) return null;

  // Poll until ready (max 15s)
  for (let i = 0; i < 15; i++) {
    await new Promise((r) => setTimeout(r, 1000));
    try {
      const pollRes = await fetch(`${DS_API}/api/v0/file/fetch_files?file_ids=${fileId}`, {
        headers: { "authorization": `Bearer ${token}`, "x-app-version": "20241129.1", "x-client-platform": "web" },
      });
      const pollData = await pollRes.json();
      const files = pollData?.data?.biz_data?.files || pollData?.data?.files || [];
      const file = files.find((f) => f.id === fileId || f.file_id === fileId);
      const status = (file?.status || "").toLowerCase();
      if (["processed", "ready", "done", "available", "success", "completed", "finished"].includes(status)) {
        console.log(`[ds-cache] [schema-file] uploaded ${content.length} chars → ${fileId} in ${Date.now() - t0}ms`);
        return fileId;
      }
    } catch { /* retry */ }
  }
  return null;
}

// ─── Session Pool ────────────────────────────────────────────────────────────
// Key: tokenHash → [{ sessionId, toolSchemaFileId, createdAt }]
const sessionPool = new Map();
const SESSION_TTL_MS = 10 * 60 * 1000; // 10 min max age
const MAX_SESSIONS_PER_ACCOUNT = 3;

function sessionPoolKey(token) {
  return token.slice(0, 16);
}

function getCachedSession(token) {
  const key = sessionPoolKey(token);
  const pool = sessionPool.get(key) || [];
  while (pool.length > 0) {
    const session = pool.shift();
    if (Date.now() - session.createdAt < SESSION_TTL_MS) {
      if (pool.length === 0) sessionPool.delete(key);
      else sessionPool.set(key, pool);
      return session;
    }
    // expired, discard
  }
  return null;
}

async function createSession(token) {
  const t0 = Date.now();
  const res = await fetch(`${DS_API}/api/v0/chat_session/create`, {
    method: "POST",
    headers: {
      "authorization": `Bearer ${token}`,
      "content-type": "application/json",
      "x-app-version": "20241129.1",
      "x-client-platform": "web",
      "x-client-version": "1.8.0",
    },
    body: JSON.stringify({ agent: "chat", character_id: null }),
  });
  const data = await res.json();
  const sessionId = data?.data?.biz_data?.chat_session?.id;
  if (!sessionId) return null;
  return { sessionId, createdAt: Date.now(), ms: Date.now() - t0 };
}

async function preCreateSession(token) {
  const key = sessionPoolKey(token);
  const pool = sessionPool.get(key) || [];
  const valid = pool.filter((s) => Date.now() - s.createdAt < SESSION_TTL_MS);
  if (valid.length >= MAX_SESSIONS_PER_ACCOUNT) return;

  try {
    const session = await createSession(token);
    if (!session) return;

    // Pre-upload tool schemas to this session (if schemas are cached)
    let toolSchemaFileId = null;
    if (cachedToolSchemas) {
      try {
        toolSchemaFileId = await uploadToolSchemaFile(token, session.sessionId);
      } catch (e) {
        console.warn(`[ds-cache] [session] schema upload failed: ${e.message}`);
      }
    }

    valid.push({ ...session, toolSchemaFileId });
    sessionPool.set(key, valid);
    console.log(
      `[ds-cache] [session] pre-created in ${session.ms}ms` +
      (toolSchemaFileId ? ` + schema file ${toolSchemaFileId}` : " (no schemas)") +
      ` (pool=${valid.length}/${MAX_SESSIONS_PER_ACCOUNT})`
    );
  } catch (e) {
    console.warn(`[ds-cache] [session] pre-create failed: ${e.message}`);
  }
}

// ─── Account Registry ────────────────────────────────────────────────────────
let accounts = []; // [{ token, email }]

// ─── Background Pre-Solver ───────────────────────────────────────────────────
const PATHS = ["/api/v0/chat/completion", "/api/v0/file/upload_file"];
let preSolveStats = { runs: 0, powSolved: 0, sessionsCreated: 0 };

async function backgroundPreSolve() {
  if (accounts.length === 0) return;
  preSolveStats.runs++;

  for (const acc of accounts) {
    // Pre-solve PoW for each path
    for (const path of PATHS) {
      await preSolvePow(acc.token, path);
      preSolveStats.powSolved++;
    }
    // Pre-create sessions
    await preCreateSession(acc.token);
    preSolveStats.sessionsCreated++;
  }
}

// Run every 20 seconds
setInterval(backgroundPreSolve, 20_000);

// ─── Stats ───────────────────────────────────────────────────────────────────
let stats = { powHits: 0, powMisses: 0, sessionHits: 0, sessionMisses: 0, requests: 0 };

// ─── HTTP Server ─────────────────────────────────────────────────────────────
function auth(req) {
  const secret = req.headers.get("x-ds-cache-secret") || "";
  return secret === SECRET;
}

const server = Bun.serve({
  port: PORT,
  async fetch(req) {
    const url = new URL(req.url);
    stats.requests++;

    if (url.pathname === "/health") {
      return Response.json({
        ok: true,
        accounts: accounts.length,
        powCacheSize: powCache.size,
        sessionPoolSize: [...sessionPool.values()].reduce((s, p) => s + p.length, 0),
        stats,
        preSolveStats,
        uptime: process.uptime(),
      });
    }

    if (!auth(req)) {
      return Response.json({ error: "unauthorized" }, { status: 401 });
    }

    // GET /pow?token=X&path=Y
    if (url.pathname === "/pow" && req.method === "GET") {
      const token = url.searchParams.get("token");
      const path = url.searchParams.get("path") || "/api/v0/chat/completion";
      if (!token) return Response.json({ error: "missing token" }, { status: 400 });

      const cached = getCachedPow(token, path);
      if (cached) {
        stats.powHits++;
        console.log(`[ds-cache] [pow] cache HIT for ${path} (solved ${Date.now() - cached.solvedAt}ms ago)`);
        return Response.json({ hit: true, pow: cached.solved, solvedAt: cached.solvedAt });
      }

      // Cache miss — solve on demand (still faster than Cloud Run roundtrip + solve)
      stats.powMisses++;
      console.log(`[ds-cache] [pow] cache MISS for ${path} — solving on demand`);
      const result = await fetchAndSolvePoW(token, path);
      if (!result) return Response.json({ error: "pow solve failed" }, { status: 500 });
      return Response.json({ hit: false, pow: result.solved, ms: result.ms });
    }

    // GET /session?token=X
    if (url.pathname === "/session" && req.method === "GET") {
      const token = url.searchParams.get("token");
      if (!token) return Response.json({ error: "missing token" }, { status: 400 });

      const cached = getCachedSession(token);
      if (cached) {
        stats.sessionHits++;
        console.log(`[ds-cache] [session] cache HIT (age=${Math.round((Date.now() - cached.createdAt) / 1000)}s, schemaFile=${cached.toolSchemaFileId || "none"})`);
        return Response.json({ hit: true, sessionId: cached.sessionId, toolSchemaFileId: cached.toolSchemaFileId || null, createdAt: cached.createdAt });
      }

      // Cache miss — create on demand (no schema upload on-demand, too slow)
      stats.sessionMisses++;
      console.log(`[ds-cache] [session] cache MISS — creating on demand`);
      const session = await createSession(token);
      if (!session) return Response.json({ error: "session create failed" }, { status: 500 });
      return Response.json({ hit: false, sessionId: session.sessionId, toolSchemaFileId: null, ms: session.ms });
    }

    // POST /tool-schemas — cache the compressed tool schemas for pre-upload
    if (url.pathname === "/tool-schemas" && req.method === "POST") {
      const body = await req.json();
      cachedToolSchemas = body.schemas;
      console.log(`[ds-cache] [tool-schemas] cached ${(cachedToolSchemas || []).length} tool schemas (${JSON.stringify(cachedToolSchemas).length} chars)`);
      return Response.json({ ok: true, count: (cachedToolSchemas || []).length });
    }

    // POST /accounts — update account list for pre-solving
    if (url.pathname === "/accounts" && req.method === "POST") {
      const body = await req.json();
      accounts = (body.accounts || []).map((a) => ({
        token: a.token,
        email: a.email || "unknown",
      }));
      console.log(`[ds-cache] [accounts] updated: ${accounts.length} accounts (${accounts.map((a) => a.email).join(", ")})`);
      // Trigger immediate pre-solve
      backgroundPreSolve().catch(() => {});
      return Response.json({ ok: true, count: accounts.length });
    }

    // GET /stats
    if (url.pathname === "/stats") {
      const powEntries = [...powCache.entries()].map(([key, val]) => ({
        key,
        ageMs: Date.now() - val.solvedAt,
        expiresInMs: val.expireAt - Date.now(),
      }));
      const sessionEntries = [...sessionPool.entries()].map(([key, pool]) => ({
        key,
        count: pool.length,
        ages: pool.map((s) => Math.round((Date.now() - s.createdAt) / 1000) + "s"),
      }));
      return Response.json({
        stats,
        preSolveStats,
        pow: { size: powCache.size, entries: powEntries },
        sessions: { size: sessionPool.size, entries: sessionEntries },
        accounts: accounts.map((a) => a.email),
      });
    }

    return Response.json({ error: "not found" }, { status: 404 });
  },
});

console.log(`\n╔══════════════════════════════════════════╗`);
console.log(`║  ds-cache — DeepSeek Warm Cache Service  ║`);
console.log(`║  Port: ${PORT}                              ║`);
console.log(`║  PoW pre-solve: every 20s per account    ║`);
console.log(`║  Session pool: max ${MAX_SESSIONS_PER_ACCOUNT} per account         ║`);
console.log(`╚══════════════════════════════════════════╝\n`);
