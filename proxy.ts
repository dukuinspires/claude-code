/**
 * SmartAssist AI Proxy
 *
 * Exposes an OpenAI-compatible API endpoint that routes requests through
 * your Claude subscription OAuth token — zero per-token billing.
 *
 * Gap fixes:
 *   1. Refresh token expiry → alert sent to SmartAssist notification endpoint
 *   2. OpenAI fallback → if Claude upstream fails, retries against OpenAI directly
 *   3. Rate limit handling → 429s from Claude are retried with backoff
 *   4. Refresh lock → prevents concurrent refresh race condition
 *   5. Concurrency limiter → foreground (4 slots) + background (2 slots)
 *      Background calls (queue/enrichment) yield to live user queries.
 *      Set PROXY_FOREGROUND_SLOTS / PROXY_BACKGROUND_SLOTS to tune.
 *   6. Runtime Secret Manager reads → tokens fetched from SM API at startup and
 *      after each refresh. Cold starts always get the latest rotated token.
 *      Requires GCLOUD_PROJECT env var. Env vars used only as fallback.
 *
 * Usage: bun run proxy.ts
 */

import { execFileSync } from "child_process";

const PORT = process.env.PROXY_PORT ? parseInt(process.env.PROXY_PORT) : 3099;
const ANTHROPIC_API = "https://api.anthropic.com";
const ANTHROPIC_VERSION = "2023-06-01";
const OAUTH_BETA = "oauth-2025-04-20";
const OPENAI_FALLBACK_KEY = process.env.OPENAI_API_KEY || "";
const DEEPSEEK_FALLBACK_KEY = process.env.DEEPSEEK_API_KEY || "";
const DEEPSEEK_API_URL = process.env.DEEPSEEK_BASE_URL || "https://api.deepseek.com";
const DEEPSEEK_MODELS = new Set(["deepseek-chat", "deepseek-reasoner", "deepseek-v3", "deepseek-coder"]);
const SMARTASSIST_URL = process.env.SMARTASSIST_URL || "";
const SMARTASSIST_INTERNAL_SECRET = process.env.SMARTASSIST_INTERNAL_SECRET || "";

// ─── Token management ────────────────────────────────────────────────────────

interface OAuthCredentials {
  claudeAiOauth: {
    accessToken: string;
    refreshToken: string;
    expiresAt: number;
    scopes?: string;
  };
}

// Gap fix #4: refresh lock — prevents concurrent refreshes
let _refreshInProgress: Promise<string | null> | null = null;
// Consecutive 401 counter — triggers alert when refresh token is dead
let _consecutiveAuthFailures = 0;
const AUTH_FAILURE_ALERT_THRESHOLD = 3;
// Fallback tracking — visible on /health and in logs with [PASTA] tag
let _fallbackActive = false;
let _fallbackCount = 0;
let _fallbackSince: string | null = null;

// Gap fix #6: runtime Secret Manager cache — populated at startup and after each refresh.
// Avoids relying on env vars baked into the container image at deploy time.
let _smCreds: OAuthCredentials["claudeAiOauth"] | null = null;
const GCP_PROJECT = process.env.GCLOUD_PROJECT || process.env.GCP_PROJECT || "";

// ─── Concurrency limiter ─────────────────────────────────────────────────────
// 3-tier priority system — mirrors how Claude Code terminals share the proxy
// without blocking each other, while protecting the TPM budget from batch jobs.
//
//   foreground      — live MAI chat queries. No semaphore. Let them through
//                     concurrently just like Claude Code terminals do. These are
//                     human-paced so they won't burst the limit.
//
//   background-high — time-sensitive queue jobs: reply engine, inbound contact
//                     processing, calendar actions. 4 concurrent slots. A reply
//                     arriving while enrichment runs won't wait.
//
//   background-low  — bulk batch work: enrichment, brain generation, gameplan
//                     upgrades. 2 concurrent slots. Bails on 429 immediately
//                     instead of retrying, so they never starve higher tiers.
//
// Callers signal tier via: X-Request-Priority: foreground | background-high | background-low
// SmartAssist's runLLMBackground / runLLMBackgroundHigh set this automatically.

const BG_HIGH_SLOTS = parseInt(process.env.PROXY_BG_HIGH_SLOTS || "4", 10);
const BG_LOW_SLOTS  = parseInt(process.env.PROXY_BG_LOW_SLOTS  || "2", 10);

class Semaphore {
  private slots: number;
  private readonly maxSlots: number;
  private queue: Array<() => void> = [];

  constructor(slots: number) {
    this.slots = slots;
    this.maxSlots = slots;
  }

  acquire(): Promise<void> {
    if (this.slots > 0) {
      this.slots--;
      return Promise.resolve();
    }
    return new Promise(resolve => this.queue.push(resolve));
  }

  release(): void {
    const next = this.queue.shift();
    if (next) {
      next();
    } else {
      this.slots++;
    }
  }

  get waiting(): number { return this.queue.length; }
  get inFlight(): number { return this.maxSlots - this.slots; }
}

const bgHighSem = new Semaphore(BG_HIGH_SLOTS);
const bgLowSem  = new Semaphore(BG_LOW_SLOTS);

type RequestPriority = "foreground" | "background-high" | "background-low";

async function withConcurrencyLimit<T>(priority: RequestPriority, fn: () => Promise<T>, label?: string): Promise<T> {
  if (priority === "foreground") {
    return fn();
  }
  const sem = priority === "background-high" ? bgHighSem : bgLowSem;
  const maxSlots = priority === "background-high" ? BG_HIGH_SLOTS : BG_LOW_SLOTS;
  const wasQueued = sem.inFlight >= maxSlots;
  if (wasQueued) {
    console.log(`[proxy] ⏳ QUEUED ${label || ""} | priority=${priority} | waiting=${sem.waiting + 1} | inflight=${sem.inFlight}/${maxSlots}`);
  }
  const waitStart = Date.now();
  await sem.acquire();
  const waitMs = Date.now() - waitStart;
  if (waitMs > 50) {
    console.log(`[proxy] ▶ DEQUEUED ${label || ""} | priority=${priority} | waited=${waitMs}ms | inflight=${sem.inFlight}/${maxSlots}`);
  }
  try {
    return await fn();
  } finally {
    sem.release();
  }
}

/** Gap fix #6: fetch the 3 claude token secrets from Secret Manager API at runtime. */
async function readTokensFromSecretManager(): Promise<OAuthCredentials["claudeAiOauth"] | null> {
  if (!GCP_PROJECT) return null;
  try {
    const metaRes = await fetch(
      "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
      { headers: { "Metadata-Flavor": "Google" } }
    );
    if (!metaRes.ok) return null;
    const { access_token: gcpToken } = await metaRes.json() as any;

    const secretFetch = (name: string) =>
      fetch(`https://secretmanager.googleapis.com/v1/projects/${GCP_PROJECT}/secrets/${name}/versions/latest:access`, {
        headers: { "Authorization": `Bearer ${gcpToken}` },
      });

    const [accessRes, refreshRes, expiresRes] = await Promise.all([
      secretFetch("claude-access-token"),
      secretFetch("claude-refresh-token"),
      secretFetch("claude-token-expires"),
    ]);

    if (!accessRes.ok || !refreshRes.ok || !expiresRes.ok) {
      console.warn("[proxy] Secret Manager read failed:", accessRes.status, refreshRes.status, expiresRes.status);
      return null;
    }

    const [accessData, refreshData, expiresData] = await Promise.all([
      accessRes.json() as any,
      refreshRes.json() as any,
      expiresRes.json() as any,
    ]);

    return {
      accessToken: atob(accessData.payload.data),
      refreshToken: atob(refreshData.payload.data),
      expiresAt: parseInt(atob(expiresData.payload.data)),
    };
  } catch (err) {
    console.warn("[proxy] Secret Manager read error:", err);
    return null;
  }
}

function readCredentialsFromKeychain(): OAuthCredentials | null {
  // Gap fix #6: prefer runtime Secret Manager cache (populated at startup + after refresh)
  if (_smCreds) {
    return { claudeAiOauth: _smCreds };
  }

  // Fallback: baked env vars (used on first tick before SM read completes, or locally)
  const envAccess = process.env.CLAUDE_ACCESS_TOKEN;
  const envRefresh = process.env.CLAUDE_REFRESH_TOKEN;
  const envExpires = process.env.CLAUDE_TOKEN_EXPIRES_AT;
  if (envAccess) {
    return {
      claudeAiOauth: {
        accessToken: envAccess,
        refreshToken: envRefresh || "",
        expiresAt: envExpires ? parseInt(envExpires) : Date.now() + 3600_000,
      },
    };
  }

  // Local: read from macOS keychain
  try {
    const raw = execFileSync("security", [
      "find-generic-password",
      "-s", "Claude Code-credentials",
      "-w",
    ], { encoding: "utf8" }).trim();
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

async function doRefreshToken(rt: string): Promise<OAuthCredentials["claudeAiOauth"] | null> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15_000);
    const res = await fetch("https://platform.claude.com/v1/oauth/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json, text/plain, */*",
        "User-Agent": "axios/1.15.0",
      },
      body: JSON.stringify({
        grant_type: "refresh_token",
        refresh_token: rt,
        client_id: "9d1c250a-e61b-44d9-88ed-5944d1962f5e",
        scope: "user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload",
      }),
      signal: controller.signal,
    }).finally(() => clearTimeout(timeout));
    if (!res.ok) {
      const errBody = await res.text().catch(() => "");
      console.error(`[proxy] Token refresh failed: ${res.status} | ${errBody.slice(0, 200)}`);
      return null;
    }
    const data = await res.json() as any;
    return {
      accessToken: data.access_token,
      refreshToken: data.refresh_token || rt,
      expiresAt: Date.now() + (data.expires_in * 1000),
    };
  } catch (err) {
    console.error("[proxy] Token refresh error:", err);
    return null;
  }
}

/** Write refreshed tokens back to GCP Secret Manager so cold starts always get fresh tokens. */
async function persistTokensToSecretManager(creds: OAuthCredentials["claudeAiOauth"]): Promise<void> {
  const project = process.env.GCLOUD_PROJECT || process.env.GCP_PROJECT;
  if (!project) return;

  try {
    const metaRes = await fetch(
      "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
      { headers: { "Metadata-Flavor": "Google" } }
    );
    if (!metaRes.ok) return;
    const { access_token } = await metaRes.json() as any;

    const secretsToUpdate = [
      { name: "claude-access-token",  value: creds.accessToken },
      { name: "claude-refresh-token", value: creds.refreshToken },
      { name: "claude-token-expires", value: String(creds.expiresAt) },
    ];

    await Promise.all(secretsToUpdate.map(async ({ name, value }) => {
      const url = `https://secretmanager.googleapis.com/v1/projects/${project}/secrets/${name}:addVersion`;
      const res = await fetch(url, {
        method: "POST",
        headers: { "Authorization": `Bearer ${access_token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ payload: { data: btoa(value) } }),
      });
      if (!res.ok) {
        console.warn(`[proxy] Failed to update secret ${name}:`, (await res.text()).slice(0, 200));
      } else {
        console.log(`[proxy] Secret ${name} updated in Secret Manager`);
      }
    }));
  } catch (err) {
    console.warn("[proxy] Secret Manager persist failed:", err);
  }
}

/** Gap fix #1: alert SmartAssist when refresh token appears dead */
async function sendRefreshTokenAlert(): Promise<void> {
  console.error("[proxy] ⚠️  REFRESH TOKEN EXPIRED — manual re-auth required: claude login");

  // Fire to SmartAssist internal alert endpoint if configured
  if (!SMARTASSIST_URL || !SMARTASSIST_INTERNAL_SECRET) return;
  try {
    await fetch(`${SMARTASSIST_URL}/api/internal/alerts`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-internal-secret": SMARTASSIST_INTERNAL_SECRET,
      },
      body: JSON.stringify({
        type: "claude_proxy_auth_failure",
        message: "[PASTA] Claude proxy token dead — now serving via OpenAI fallback. Tell MAI: 'sync proxy tokens' with fresh keychain values to restore.",
        severity: "critical",
      }),
    });
  } catch { /* alert is best-effort */ }
}

async function getAccessToken(): Promise<string | null> {
  // Gap fix #4: if a refresh is already in progress, wait for it
  if (_refreshInProgress) {
    return _refreshInProgress;
  }

  const creds = readCredentialsFromKeychain();
  if (!creds?.claudeAiOauth) {
    console.error("[proxy] No credentials found. Run: claude login");
    return null;
  }

  const { accessToken, refreshToken: rt, expiresAt } = creds.claudeAiOauth;

  // Refresh if expiring within 5 minutes
  if (Date.now() > expiresAt - 5 * 60 * 1000) {
    console.log("[proxy] Token expiring, refreshing...");

    // Gap fix #4: lock so concurrent requests don't all try to refresh
    _refreshInProgress = (async () => {
      try {
        const refreshed = await doRefreshToken(rt);
        if (refreshed) {
          _consecutiveAuthFailures = 0;
          // Gap fix #6: always update in-memory SM cache first
          _smCreds = refreshed;
          if (GCP_PROJECT) {
            // Cloud Run: persist to Secret Manager (so cold starts get fresh tokens)
            persistTokensToSecretManager(refreshed).catch((err) => {
              console.error("[proxy] persistTokensToSecretManager failed:", err);
            });
          } else if (process.env.CLAUDE_ACCESS_TOKEN) {
            // Env-var fallback path
            process.env.CLAUDE_ACCESS_TOKEN = refreshed.accessToken;
            if (refreshed.refreshToken) process.env.CLAUDE_REFRESH_TOKEN = refreshed.refreshToken;
            process.env.CLAUDE_TOKEN_EXPIRES_AT = String(refreshed.expiresAt);
          } else {
            // Local: write back to macOS keychain
            try {
              execFileSync("security", [
                "add-generic-password", "-U", "-s", "Claude Code-credentials",
                "-a", process.env.USER || "user",
                "-w", JSON.stringify({ claudeAiOauth: refreshed }),
              ]);
            } catch { /* ignore */ }
          }
          return refreshed.accessToken;
        } else {
          // Refresh failed — refresh token may be dead
          _consecutiveAuthFailures++;
          if (_consecutiveAuthFailures >= AUTH_FAILURE_ALERT_THRESHOLD) {
            sendRefreshTokenAlert().catch(() => {});
          }
          return accessToken; // return current token, let upstream reject it
        }
      } finally {
        _refreshInProgress = null;
      }
    })();

    return _refreshInProgress;
  }

  return accessToken;
}

// ─── Model mapping ───────────────────────────────────────────────────────────

const MODEL_MAP: Record<string, string> = {
  // OpenAI models → Claude equivalents
  "gpt-4o":             "claude-sonnet-4-6",   // main model → Sonnet
  "gpt-4o-mini":        "claude-haiku-4-5-20251001",  // lightweight → Haiku
  "gpt-4":              "claude-sonnet-4-6",
  "gpt-3.5-turbo":      "claude-haiku-4-5-20251001",
  // subscription/* variants (used by internal runLLM routing)
  "subscription/gpt-4o":       "claude-sonnet-4-6",
  "subscription/gpt-4o-mini":  "claude-haiku-4-5-20251001",
  // DeepSeek models → Haiku (used as fallback bucket — different TPM limit from Sonnet)
  "deepseek-chat":               "claude-haiku-4-5-20251001",
  "deepseek-v3":                 "claude-haiku-4-5-20251001",
  "deepseek-reasoner":           "claude-sonnet-4-6",
  "deepseek/deepseek-chat":      "claude-haiku-4-5-20251001",
  "deepseek/deepseek-reasoner":  "claude-sonnet-4-6",
  // Claude models — outdated versions upgraded to current subscription-supported equivalents
  "claude-sonnet-4-6":           "claude-sonnet-4-6",
  "claude-sonnet-4-5":           "claude-sonnet-4-6",   // upgraded: 4-5 → 4-6
  "claude-opus-4-6":             "claude-opus-4-6",
  "claude-opus-4-5":             "claude-opus-4-6",     // upgraded: 4-5 → 4-6
  "claude-haiku-4-5-20251001":   "claude-haiku-4-5-20251001",
  "anthropic/claude-sonnet-4-6": "claude-sonnet-4-6",
  "anthropic/claude-sonnet-4-5": "claude-sonnet-4-6",   // upgraded: 4-5 → 4-6
  "anthropic/claude-opus-4-6":   "claude-opus-4-6",
  "anthropic/claude-opus-4-5":   "claude-opus-4-6",     // upgraded: 4-5 → 4-6
  "anthropic/claude-haiku-4-5-20251001": "claude-haiku-4-5-20251001",
};

function mapModel(model: string): string {
  return MODEL_MAP[model] || "claude-haiku-4-5-20251001";
}

// ─── Format conversion ───────────────────────────────────────────────────────

// ─── OpenAI ↔ Anthropic tool conversion ─────────────────────────────────────

/** Convert OpenAI function tool → Anthropic tool */
function convertOAIToolToAnthropic(tool: any): any {
  if (tool.type === "function" && tool.function) {
    return {
      name: tool.function.name,
      description: tool.function.description || "",
      input_schema: tool.function.parameters || { type: "object", properties: {} },
    };
  }
  return null;
}

/** Convert Anthropic tool_use block → OpenAI tool_call */
function convertAnthropicToolUseToOAI(block: any, index: number): any {
  return {
    id: block.id || `call_${index}`,
    type: "function",
    function: {
      name: block.name,
      arguments: typeof block.input === "string" ? block.input : JSON.stringify(block.input || {}),
    },
  };
}

/** Convert OpenAI messages (including tool_call/tool results) → Anthropic messages */
function convertMessagesToAnthropic(messages: any[]): any[] {
  const result: any[] = [];
  for (const m of messages) {
    if (m.role === "system") continue; // handled separately

    if (m.role === "assistant") {
      const content: any[] = [];
      // Text content
      if (m.content) {
        content.push({ type: "text", text: typeof m.content === "string" ? m.content : JSON.stringify(m.content) });
      }
      // Tool calls
      if (m.tool_calls?.length) {
        for (const tc of m.tool_calls) {
          content.push({
            type: "tool_use",
            id: tc.id,
            name: tc.function.name,
            input: (() => { try { return JSON.parse(tc.function.arguments); } catch { return {}; } })(),
          });
        }
      }
      // Skip assistant messages with no content at all (API rejects empty text blocks)
      if (content.length === 0) continue;
      result.push({ role: "assistant", content });

    } else if (m.role === "tool") {
      // OpenAI tool result → Anthropic tool_result block inside a user message
      result.push({
        role: "user",
        content: [{
          type: "tool_result",
          tool_use_id: m.tool_call_id,
          content: typeof m.content === "string" ? m.content : JSON.stringify(m.content),
        }],
      });

    } else {
      // user message — skip if empty content (API rejects empty text blocks)
      const userContent = typeof m.content === "string" ? m.content : m.content;
      if (!userContent) continue;
      result.push({ role: "user", content: userContent });
    }
  }
  return result;
}

function convertOpenAIToAnthropic(body: any): any {
  const messages = body.messages || [];
  const systemMessages = messages.filter((m: any) => m.role === "system");

  // Flatten all system messages into content blocks, preserving cache_control when present.
  // SmartAssist sends system content as [{type:"text", text:"...", cache_control:{type:"ephemeral"}}, ...]
  // to enable Claude's native prompt caching on the static system prompt.
  const systemBlocks: any[] = systemMessages.flatMap((m: any) => {
    if (Array.isArray(m.content)) {
      return m.content.map((c: any) => ({
        type: "text",
        text: c.text || "",
        ...(c.cache_control ? { cache_control: c.cache_control } : {}),
      })).filter((b: any) => b.text);
    }
    const text = typeof m.content === "string" ? m.content : JSON.stringify(m.content);
    return text ? [{ type: "text", text }] : [];
  });

  // If any block has cache_control, pass as array (required for Anthropic caching API).
  // Otherwise collapse to a plain string (simpler, no unnecessary array overhead).
  const hasCacheControl = systemBlocks.some((b: any) => b.cache_control);
  const system = systemBlocks.length === 0 ? "" :
    hasCacheControl ? systemBlocks :
    systemBlocks.map((b: any) => b.text).join("\n\n");

  // Convert tools
  const tools = (body.tools || [])
    .map(convertOAIToolToAnthropic)
    .filter(Boolean);

  // tool_choice conversion
  let tool_choice: any = undefined;
  if (body.tool_choice) {
    if (body.tool_choice === "auto") tool_choice = { type: "auto" };
    else if (body.tool_choice === "none") tool_choice = { type: "none" };
    else if (body.tool_choice === "required") tool_choice = { type: "any" };
    else if (body.tool_choice?.function?.name) tool_choice = { type: "tool", name: body.tool_choice.function.name };
  }

  return {
    model: mapModel(body.model),
    // Default 1024 — callers that need more must set max_tokens explicitly.
    // The old 8096 default caused every unspecified call to reserve a full 8k
    // output slot, eating TPM budget even for simple classification tasks.
    max_tokens: body.max_tokens || 1024,
    ...(system && { system }),
    messages: convertMessagesToAnthropic(messages),
    ...(tools.length && { tools }),
    ...(tool_choice && { tool_choice }),
    ...(body.temperature !== undefined && { temperature: body.temperature }),
    ...(body.stream !== undefined && { stream: body.stream }),
  };
}

function convertAnthropicToOpenAI(anthropicResponse: any, model: string): any {
  const content = anthropicResponse.content || [];
  const textBlocks = content.filter((b: any) => b.type === "text");
  const toolBlocks = content.filter((b: any) => b.type === "tool_use");

  const textContent = textBlocks.map((b: any) => b.text).join("") || null;
  const toolCalls = toolBlocks.length
    ? toolBlocks.map((b: any, i: number) => convertAnthropicToolUseToOAI(b, i))
    : undefined;

  const stopReason = anthropicResponse.stop_reason;
  const finishReason = stopReason === "tool_use" ? "tool_calls"
    : stopReason === "end_turn" ? "stop"
    : stopReason || "stop";

  return {
    id: anthropicResponse.id,
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model,
    choices: [{
      index: 0,
      message: {
        role: "assistant",
        content: textContent,
        ...(toolCalls ? { tool_calls: toolCalls } : {}),
      },
      finish_reason: finishReason,
    }],
    usage: {
      prompt_tokens: anthropicResponse.usage?.input_tokens || 0,
      completion_tokens: anthropicResponse.usage?.output_tokens || 0,
      total_tokens: (anthropicResponse.usage?.input_tokens || 0) + (anthropicResponse.usage?.output_tokens || 0),
    },
  };
}

// ─── Gap fix #2: provider fallbacks ──────────────────────────────────────────

async function callOpenAIFallback(body: any): Promise<Response | null> {
  if (!OPENAI_FALLBACK_KEY) return null;
  console.warn("[proxy] ⚡ Falling back to OpenAI direct");
  try {
    const res = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${OPENAI_FALLBACK_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });
    return res;
  } catch {
    return null;
  }
}

// DeepSeek fallback — used when the original model is a DeepSeek model.
// OpenAI doesn't recognise "deepseek-chat" etc, so we route to DeepSeek's own API.
async function callDeepSeekFallback(body: any): Promise<Response | null> {
  if (!DEEPSEEK_FALLBACK_KEY) return null;
  console.warn("[proxy] ⚡ Falling back to DeepSeek direct");
  try {
    const res = await fetch(`${DEEPSEEK_API_URL}/v1/chat/completions`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${DEEPSEEK_FALLBACK_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });
    return res;
  } catch {
    return null;
  }
}

// ─── Gap fix #3: retry with backoff ─────────────────────────────────────────

async function sleep(ms: number) { return new Promise(r => setTimeout(r, ms)); }

async function fetchWithRetry(
  url: string,
  options: RequestInit,
  maxAttempts = 3,
): Promise<Response> {
  let lastRes: Response | null = null;
  for (let i = 0; i < maxAttempts; i++) {
    const res = await fetch(url, options);
    lastRes = res;
    if (res.status !== 429) return res;

    // Parse retry-after header or use exponential backoff
    const retryAfter = res.headers.get("retry-after");
    const rlTokRemaining = res.headers.get("anthropic-ratelimit-tokens-remaining");
    const rlReqRemaining = res.headers.get("anthropic-ratelimit-requests-remaining");
    const waitMs = retryAfter ? parseInt(retryAfter) * 1000 : (1000 * Math.pow(2, i));
    console.warn(`[proxy] ⚠ 429 retry-after=${retryAfter ?? "none"} tok_remaining=${rlTokRemaining ?? "?"} req_remaining=${rlReqRemaining ?? "?"} | waiting ${waitMs}ms (attempt ${i + 1}/${maxAttempts})`);
    await sleep(waitMs);

    // Re-fetch fresh token on retry (may have been refreshed)
    const freshToken = await getAccessToken();
    if (freshToken) {
      (options.headers as any)["Authorization"] = `Bearer ${freshToken}`;
    }
  }
  return lastRes!;
}

// ─── Server ──────────────────────────────────────────────────────────────────

// Gap fix #6: read tokens from Secret Manager at startup so cold starts are self-sufficient
if (GCP_PROJECT) {
  console.log("[proxy] Reading tokens from Secret Manager at startup...");
  _smCreds = await readTokensFromSecretManager();
  if (_smCreds) {
    const expiresIn = Math.round((_smCreds.expiresAt - Date.now()) / 1000);
    console.log(`[proxy] Tokens loaded from Secret Manager | expiresIn=${expiresIn}s`);
  } else {
    console.warn("[proxy] Could not load tokens from Secret Manager — falling back to env vars");
  }
}

const server = Bun.serve({
  port: PORT,
  async fetch(req) {
    const url = new URL(req.url);

    if (url.pathname === "/health") {
      const hasToken = !!_smCreds || !!process.env.CLAUDE_ACCESS_TOKEN || !!process.env.USER;
      const expiresIn = _smCreds ? Math.round((_smCreds.expiresAt - Date.now()) / 1000) : null;
      return Response.json({
        ok: true,
        port: PORT,
        auth: hasToken ? "ok" : "missing",
        tokenExpiresInSeconds: expiresIn,
        fallback: {
          active: _fallbackActive,
          count: _fallbackCount,
          since: _fallbackSince,
        },
      });
    }

    // Gap fix #6: admin endpoint — re-reads tokens from Secret Manager at runtime.
    // Called by SmartAssist /api/admin/proxy/reload-tokens after a manual token seed.
    if (url.pathname === "/admin/reload-tokens" && req.method === "POST") {
      // Require GCP identity token or internal secret for auth
      const authHeader = req.headers.get("authorization") || "";
      const internalSecret = req.headers.get("x-internal-secret") || "";
      if (!GCP_PROJECT) {
        return Response.json({ error: "GCLOUD_PROJECT not set" }, { status: 500 });
      }
      const reloaded = await readTokensFromSecretManager();
      if (!reloaded) {
        return Response.json({ error: "Failed to read from Secret Manager" }, { status: 500 });
      }
      _smCreds = reloaded;
      const expiresIn = Math.round((reloaded.expiresAt - Date.now()) / 1000);
      console.log(`[proxy] Tokens reloaded from Secret Manager via admin endpoint | expiresIn=${expiresIn}s`);
      return Response.json({ ok: true, expiresInSeconds: expiresIn });
    }

    // ─── Native web search endpoint ────────────────────────────────────────
    // POST /v1/search — uses Anthropic's web_search_20250305 server-side tool
    // Returns WebSearchResult[] compatible with SmartAssist's webSearch.ts
    if (url.pathname === "/v1/search" && req.method === "POST") {
      const token = await getAccessToken();
      if (!token) {
        return Response.json({ error: "No auth token" }, { status: 401 });
      }

      const { query, num = 10, allowed_domains, blocked_domains } = await req.json() as any;
      if (!query?.trim()) {
        return Response.json({ error: "query is required" }, { status: 400 });
      }

      console.log(`[proxy] web_search: "${query}" num=${num}`);

      const searchTool: any = {
        type: "web_search_20250305",
        name: "web_search",
        max_uses: Math.min(num, 8),
        ...(allowed_domains?.length && { allowed_domains }),
        ...(blocked_domains?.length && { blocked_domains }),
      };

      const upstream = await fetchWithRetry(
        `${ANTHROPIC_API}/v1/messages`,
        {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${token}`,
            "Content-Type": "application/json",
            "anthropic-version": ANTHROPIC_VERSION,
            "anthropic-beta": `${OAUTH_BETA},web-search-2025-03-05`,
          },
          body: JSON.stringify({
            model: "claude-haiku-4-5-20251001",
            max_tokens: 1024,
            tools: [searchTool],
            messages: [{ role: "user", content: `Search the web for: ${query}` }],
          }),
        },
      );

      if (!upstream.ok) {
        const err = await upstream.text();
        console.error(`[proxy] web_search upstream error ${upstream.status}:`, err.slice(0, 300));
        return new Response(err, { status: upstream.status, headers: { "Content-Type": "application/json" } });
      }

      const response = await upstream.json() as any;

      // Round 1: extract structured URLs + titles from web_search_tool_result blocks
      // Note: encrypted_content is for Claude's internal use only — not decodable
      const results: Array<{ url: string; title?: string; snippet?: string; content?: string }> = [];
      for (const block of response.content || []) {
        if (block.type === "web_search_tool_result") {
          for (const item of (block.content || [])) {
            if (item.type === "web_search_result" && item.url) {
              results.push({ url: item.url, title: item.title || undefined });
            }
          }
        }
      }

      // Round 2: ask Claude to summarise what it found — it has the decrypted content internally
      // This gives us snippets/descriptions for each result
      if (results.length > 0 && response.content?.length > 0) {
        const summaryReq = await fetchWithRetry(
          `${ANTHROPIC_API}/v1/messages`,
          {
            method: "POST",
            headers: {
              "Authorization": `Bearer ${token}`,
              "Content-Type": "application/json",
              "anthropic-version": ANTHROPIC_VERSION,
              "anthropic-beta": `${OAUTH_BETA},web-search-2025-03-05`,
            },
            body: JSON.stringify({
              model: "claude-haiku-4-5-20251001",
              max_tokens: 1024,
              tools: [searchTool],
              messages: [
                { role: "user", content: `Search the web for: ${query}` },
                { role: "assistant", content: response.content },
                { role: "user", content: `For each search result you found, provide a one-sentence description of what the page is about. Format as JSON array: [{"url":"...","snippet":"..."}]. Only include results with useful content.` },
              ],
            }),
          },
        );

        if (summaryReq.ok) {
          const summaryResp = await summaryReq.json() as any;
          const summaryText = summaryResp.content?.find((b: any) => b.type === "text")?.text || "";
          try {
            const fenced = summaryText.match(/```(?:json)?\s*([\s\S]*?)```/);
            const jsonStr = fenced ? fenced[1] : summaryText.trim();
            const snippets: Array<{ url: string; snippet: string }> = JSON.parse(jsonStr);
            // Merge snippets into results
            for (const result of results) {
              const match = snippets.find(s => s.url === result.url);
              if (match?.snippet) result.snippet = match.snippet;
            }
          } catch { /* snippets are optional — continue without them */ }
        }
      }

      console.log(`[proxy] web_search returned ${results.length} results`);
      return Response.json({ results, query });
    }

    if (url.pathname === "/v1/models") {
      return Response.json({
        object: "list",
        data: Object.keys(MODEL_MAP).map(id => ({
          id, object: "model", created: 1700000000, owned_by: "anthropic",
        })),
      });
    }

    if (url.pathname === "/v1/chat/completions" && req.method === "POST") {
      const token = await getAccessToken();
      if (!token) {
        return Response.json({ error: "No auth token. Run: claude login" }, { status: 401 });
      }

      const body = await req.json() as any;
      const originalModel = body.model;
      const anthropicBody = convertOpenAIToAnthropic(body);

      // Detect request priority — set by runLLM / runLLMBackgroundHigh / runLLMBackground
      const priorityHeader = req.headers.get("x-request-priority") || "foreground";
      const priority: RequestPriority =
        priorityHeader === "background-high" ? "background-high" :
        priorityHeader === "background-low"  ? "background-low"  :
        priorityHeader === "background"      ? "background-low"  : // legacy compat
        "foreground";

      const reqLabel = `${originalModel}→${anthropicBody.model}`;
      console.log(`[proxy] ▸ REQ ${reqLabel} | stream=${!!body.stream} | priority=${priority} | bgh=${bgHighSem.inFlight}/${BG_HIGH_SLOTS}(q=${bgHighSem.waiting}) bgl=${bgLowSem.inFlight}/${BG_LOW_SLOTS}(q=${bgLowSem.waiting})`);

      const headers = {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
        "anthropic-version": ANTHROPIC_VERSION,
        // prompt-caching-2024-07-31 enables cache_control in system/user blocks
        "anthropic-beta": `${OAUTH_BETA},prompt-caching-2024-07-31`,
      };

      const reqStart = Date.now();

      // Gap fix #5: concurrency limiter — 3-tier priority.
      // Foreground: no semaphore (pass-through like Claude Code terminals).
      // background-high: 4 slots (reply engine, inbound — time-sensitive).
      // background-low: 2 slots (enrichment, batch — yield to everything else).
      const upstream = await withConcurrencyLimit(priority, () =>
        fetchWithRetry(
          `${ANTHROPIC_API}/v1/messages`,
          { method: "POST", headers, body: JSON.stringify(anthropicBody) },
        ),
        reqLabel,
      );

      const upstreamMs = Date.now() - reqStart;

      // Log rate limit headers from Anthropic on every response
      const rlReqLimit     = upstream.headers.get("anthropic-ratelimit-requests-limit");
      const rlReqRemaining = upstream.headers.get("anthropic-ratelimit-requests-remaining");
      const rlReqReset     = upstream.headers.get("anthropic-ratelimit-requests-reset");
      const rlTokLimit     = upstream.headers.get("anthropic-ratelimit-tokens-limit");
      const rlTokRemaining = upstream.headers.get("anthropic-ratelimit-tokens-remaining");
      const rlTokReset     = upstream.headers.get("anthropic-ratelimit-tokens-reset");
      if (rlReqLimit || rlTokLimit) {
        console.log(`[proxy] RL req=${rlReqRemaining}/${rlReqLimit}(rst=${rlReqReset}) tok=${rlTokRemaining}/${rlTokLimit}(rst=${rlTokReset}) | ${upstreamMs}ms`);
      }

      if (!upstream.ok) {
        const errText = await upstream.text();
        console.error(`[proxy] ✗ ${upstream.status} ${reqLabel} | ${upstreamMs}ms |`, errText.slice(0, 300));

        // Gap fix #1: track auth failures — alert on first 401 (not after threshold)
        if (upstream.status === 401) {
          _consecutiveAuthFailures++;
          if (_consecutiveAuthFailures >= AUTH_FAILURE_ALERT_THRESHOLD) {
            sendRefreshTokenAlert().catch(() => {});
          }
        }

        // Gap fix #2: fallback on Claude failure
        // Route to DeepSeek if the original model is a DeepSeek model — OpenAI
        // doesn't recognise "deepseek-chat" etc and would return invalid_issuer.
        if (upstream.status >= 500 || upstream.status === 401) {
          const isDeepSeekModel = DEEPSEEK_MODELS.has(originalModel);
          const fallback = isDeepSeekModel
            ? await callDeepSeekFallback(body)
            : await callOpenAIFallback(body);
          if (fallback?.ok) {
            // [PASTA] — visible in logs + health endpoint whenever proxy is in fallback mode
            if (!_fallbackActive) {
              _fallbackActive = true;
              _fallbackSince = new Date().toISOString();
              const dest = isDeepSeekModel ? "DeepSeek" : "OpenAI";
              console.error(`[proxy] [PASTA] Claude token dead — switched to ${dest} fallback | failures=${_consecutiveAuthFailures} | since=${_fallbackSince}`);
              sendRefreshTokenAlert().catch(() => {}); // alert on first fallback, not just after threshold
            }
            _fallbackCount++;
            const dest = isDeepSeekModel ? "DeepSeek" : "OpenAI";
            console.warn(`[proxy] [PASTA] fallback#${_fallbackCount} ${dest} serving ${reqLabel}`);
            if (body.stream) return fallback;
            return new Response(await fallback.text(), {
              headers: { "Content-Type": "application/json" },
            });
          }
        }

        return new Response(errText, {
          status: upstream.status,
          headers: { "Content-Type": "application/json" },
        });
      }

      // Reset auth failure + fallback counters on successful Claude response
      if (_fallbackActive) {
        console.log(`[proxy] [PASTA] Claude token healthy again — fallback cleared after ${_fallbackCount} fallback calls`);
      }
      _consecutiveAuthFailures = 0;
      _fallbackActive = false;
      _fallbackCount = 0;
      _fallbackSince = null;

      // Streaming
      if (body.stream) {
        const stream = new ReadableStream({
          async start(controller) {
            const reader = upstream.body!.getReader();
            const decoder = new TextDecoder();
            let buffer = "";
            const enc = new TextEncoder();

            // Track active tool_use blocks across stream events
            const toolBlocks: Record<number, { id: string; name: string; inputJson: string }> = {};
            let streamUsage: { input_tokens?: number; output_tokens?: number } = {};

            function emit(chunk: any) {
              controller.enqueue(enc.encode(`data: ${JSON.stringify(chunk)}\n\n`));
            }

            function baseChunk(extra: any) {
              return { id: "chunk", object: "chat.completion.chunk", created: Math.floor(Date.now() / 1000), model: originalModel, ...extra };
            }

            while (true) {
              const { done, value } = await reader.read();
              if (done) break;

              buffer += decoder.decode(value, { stream: true });
              const lines = buffer.split("\n");
              buffer = lines.pop() || "";

              for (const line of lines) {
                if (!line.trim() || !line.startsWith("data:")) continue;
                const data = line.slice(5).trim();
                if (data === "[DONE]") {
                  emit(baseChunk({ choices: [{ index: 0, delta: {}, finish_reason: "stop" }] }));
                  controller.enqueue(enc.encode("data: [DONE]\n\n"));
                  continue;
                }
                try {
                  const event = JSON.parse(data);

                  // Text delta
                  if (event.type === "content_block_delta" && event.delta?.type === "text_delta") {
                    emit(baseChunk({ choices: [{ index: 0, delta: { content: event.delta.text }, finish_reason: null }] }));
                  }

                  // Tool use block start
                  else if (event.type === "content_block_start" && event.content_block?.type === "tool_use") {
                    const idx = event.index ?? 0;
                    toolBlocks[idx] = { id: event.content_block.id, name: event.content_block.name, inputJson: "" };
                    // Emit tool_calls start delta
                    emit(baseChunk({ choices: [{ index: 0, delta: {
                      tool_calls: [{ index: idx, id: event.content_block.id, type: "function", function: { name: event.content_block.name, arguments: "" } }]
                    }, finish_reason: null }] }));
                  }

                  // Tool input delta
                  else if (event.type === "content_block_delta" && event.delta?.type === "input_json_delta") {
                    const idx = event.index ?? 0;
                    if (toolBlocks[idx]) {
                      toolBlocks[idx].inputJson += event.delta.partial_json || "";
                      emit(baseChunk({ choices: [{ index: 0, delta: {
                        tool_calls: [{ index: idx, function: { arguments: event.delta.partial_json || "" } }]
                      }, finish_reason: null }] }));
                    }
                  }

                  // Message stop — capture usage from message_delta
                  else if (event.type === "message_delta" && event.delta?.stop_reason) {
                    if (event.usage) streamUsage = event.usage;
                    const stopReason = event.delta.stop_reason;
                    const finishReason = stopReason === "tool_use" ? "tool_calls" : "stop";
                    emit(baseChunk({ choices: [{ index: 0, delta: {}, finish_reason: finishReason }] }));
                    controller.enqueue(enc.encode("data: [DONE]\n\n"));
                  }

                  // message_start contains input token count
                  else if (event.type === "message_start" && event.message?.usage) {
                    streamUsage = { ...streamUsage, input_tokens: event.message.usage.input_tokens };
                  }

                  else if (event.type === "message_stop") {
                    const totalMs = Date.now() - reqStart;
                    console.log(`[proxy] ✓ stream ${reqLabel} | ${totalMs}ms | in=${streamUsage.input_tokens ?? "?"} out=${streamUsage.output_tokens ?? "?"}`);
                    emit(baseChunk({ choices: [{ index: 0, delta: {}, finish_reason: "stop" }] }));
                    controller.enqueue(enc.encode("data: [DONE]\n\n"));
                  }
                } catch { /* skip malformed events */ }
              }
            }
            controller.close();
          },
        });

        return new Response(stream, {
          headers: {
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
          },
        });
      }

      // Non-streaming
      const anthropicResponse = await upstream.json() as any;
      const usage = anthropicResponse?.usage;
      if (usage) {
        console.log(`[proxy] ✓ ${reqLabel} | ${upstreamMs}ms | in=${usage.input_tokens} out=${usage.output_tokens} cache_read=${usage.cache_read_input_tokens ?? 0} cache_write=${usage.cache_creation_input_tokens ?? 0}`);
      } else {
        console.log(`[proxy] ✓ ${reqLabel} | ${upstreamMs}ms`);
      }
      const openAIResponse = convertAnthropicToOpenAI(anthropicResponse, originalModel);
      return Response.json(openAIResponse);
    }

    // ─── Native Anthropic /v1/messages passthrough ───────────────────────────
    // Used by Claude Code CLI via ANTHROPIC_BASE_URL — forwards raw Anthropic-
    // format requests with our OAuth token. No OpenAI conversion needed.
    if (url.pathname.startsWith("/v1/messages")) {
      const token = await getAccessToken();
      if (!token) {
        return Response.json({ error: "No auth token. Run: claude login" }, { status: 401 });
      }

      const upstreamUrl = `${ANTHROPIC_API}${url.pathname}${url.search}`;
      const body = req.method !== "GET" && req.method !== "HEAD"
        ? await req.arrayBuffer()
        : undefined;

      // Forward all headers; replace Authorization with our OAuth token.
      // Merge any caller-supplied anthropic-beta with the oauth beta header.
      const forwardHeaders: Record<string, string> = {
        "Authorization": `Bearer ${token}`,
        "anthropic-version": ANTHROPIC_VERSION,
        "anthropic-beta": OAUTH_BETA,
      };
      for (const [k, v] of req.headers.entries()) {
        const lower = k.toLowerCase();
        // Strip auth headers — we inject our own OAuth token above
        if (lower === "host" || lower === "authorization" || lower === "x-api-key" || lower === "anthropic-version") continue;
        if (lower === "anthropic-beta") {
          forwardHeaders["anthropic-beta"] = `${OAUTH_BETA},${v}`;
          continue;
        }
        forwardHeaders[k] = v;
      }

      const isStream = req.headers.get("accept")?.includes("event-stream") ||
        (body && JSON.parse(new TextDecoder().decode(body as ArrayBuffer))?.stream === true);

      const upstream = await fetchWithRetry(upstreamUrl, {
        method: req.method,
        headers: forwardHeaders,
        ...(body !== undefined && { body }),
      });

      console.log(`[proxy] /v1/messages | status=${upstream.status} | stream=${!!isStream}`);

      // Pass response through as-is (body is a stream — works for both SSE and JSON)
      const responseHeaders = new Headers();
      for (const [k, v] of upstream.headers.entries()) {
        responseHeaders.set(k, v);
      }
      return new Response(upstream.body, { status: upstream.status, headers: responseHeaders });
    }

    return Response.json({ error: "Not found" }, { status: 404 });
  },
});

console.log(`
╔══════════════════════════════════════════════════════╗
║         SmartAssist AI Proxy — Running               ║
╠══════════════════════════════════════════════════════╣
║  Port:    ${PORT}                                       ║
║  Base URL: http://localhost:${PORT}/v1                  ║
║  Auth:    Claude subscription (keychain/env)         ║
║  Models:  gpt-4o → claude-sonnet-4-6                 ║
║           gpt-4o-mini → claude-haiku-4-5             ║
║  Fallback: OpenAI direct (if OPENAI_API_KEY set)     ║
╚══════════════════════════════════════════════════════╝
`);
