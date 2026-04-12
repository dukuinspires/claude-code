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
 *
 * Usage: bun run proxy.ts
 */

import { execFileSync } from "child_process";

const PORT = process.env.PROXY_PORT ? parseInt(process.env.PROXY_PORT) : 3099;
const ANTHROPIC_API = "https://api.anthropic.com";
const ANTHROPIC_VERSION = "2023-06-01";
const OAUTH_BETA = "oauth-2025-04-20";
const OPENAI_FALLBACK_KEY = process.env.OPENAI_API_KEY || "";
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

function readCredentialsFromKeychain(): OAuthCredentials | null {
  // Production: read from env vars (Cloud Run / Secret Manager)
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
    const res = await fetch("https://platform.claude.com/v1/oauth/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type: "refresh_token",
        refresh_token: rt,
        client_id: "9d1c250a-e61b-44d9-88ed-5944d1962f5e",
      }),
    });
    if (!res.ok) {
      console.error(`[proxy] Token refresh failed: ${res.status}`);
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
        message: "Claude subscription proxy: refresh token expired. Run `claude login` and update GCP secrets.",
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
          if (process.env.CLAUDE_ACCESS_TOKEN) {
            process.env.CLAUDE_ACCESS_TOKEN = refreshed.accessToken;
            if (refreshed.refreshToken) process.env.CLAUDE_REFRESH_TOKEN = refreshed.refreshToken;
            process.env.CLAUDE_TOKEN_EXPIRES_AT = String(refreshed.expiresAt);
            persistTokensToSecretManager(refreshed).catch(() => {});
          } else {
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
  "gpt-4o":             "claude-sonnet-4-6",
  "gpt-4o-mini":        "claude-haiku-4-5-20251001",
  "gpt-4":              "claude-sonnet-4-6",
  "gpt-3.5-turbo":      "claude-haiku-4-5-20251001",
  // DeepSeek models → Claude equivalents
  "deepseek-chat":               "claude-haiku-4-5-20251001",
  "deepseek-v3":                 "claude-haiku-4-5-20251001",
  "deepseek-reasoner":           "claude-sonnet-4-6",
  "deepseek/deepseek-chat":      "claude-haiku-4-5-20251001",
  "deepseek/deepseek-reasoner":  "claude-sonnet-4-6",
  // Claude models → pass through as-is
  "claude-sonnet-4-6":           "claude-sonnet-4-6",
  "claude-sonnet-4-5":           "claude-sonnet-4-5",
  "claude-opus-4-6":             "claude-opus-4-6",
  "claude-opus-4-5":             "claude-opus-4-5",
  "claude-haiku-4-5-20251001":   "claude-haiku-4-5-20251001",
  "anthropic/claude-sonnet-4-6": "claude-sonnet-4-6",
  "anthropic/claude-sonnet-4-5": "claude-sonnet-4-5",
  "anthropic/claude-opus-4-6":   "claude-opus-4-6",
  "anthropic/claude-opus-4-5":   "claude-opus-4-5",
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
  const system = systemMessages.map((m: any) =>
    typeof m.content === "string" ? m.content : m.content.map((c: any) => c.text || "").join("\n")
  ).join("\n\n");

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
    max_tokens: body.max_tokens || 8096,
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

// ─── Gap fix #2: OpenAI fallback ─────────────────────────────────────────────

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
    const waitMs = retryAfter ? parseInt(retryAfter) * 1000 : (1000 * Math.pow(2, i));
    console.warn(`[proxy] Rate limited (429), retrying in ${waitMs}ms (attempt ${i + 1}/${maxAttempts})`);
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

const server = Bun.serve({
  port: PORT,
  async fetch(req) {
    const url = new URL(req.url);

    if (url.pathname === "/health") {
      const hasToken = !!process.env.CLAUDE_ACCESS_TOKEN || !!process.env.USER;
      return Response.json({ ok: true, port: PORT, auth: hasToken ? "ok" : "missing" });
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

      console.log(`[proxy] ${originalModel} → ${anthropicBody.model} | stream=${!!body.stream}`);

      const headers = {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
        "anthropic-version": ANTHROPIC_VERSION,
        "anthropic-beta": OAUTH_BETA,
      };

      // Gap fix #3: use retry wrapper
      const upstream = await fetchWithRetry(
        `${ANTHROPIC_API}/v1/messages`,
        { method: "POST", headers, body: JSON.stringify(anthropicBody) },
      );

      if (!upstream.ok) {
        const errText = await upstream.text();
        console.error(`[proxy] Upstream error ${upstream.status}:`, errText.slice(0, 300));

        // Gap fix #1: track auth failures
        if (upstream.status === 401) {
          _consecutiveAuthFailures++;
          if (_consecutiveAuthFailures >= AUTH_FAILURE_ALERT_THRESHOLD) {
            sendRefreshTokenAlert().catch(() => {});
          }
        }

        // Gap fix #2: fallback to OpenAI on Claude failure
        if (upstream.status >= 500 || upstream.status === 401) {
          const fallback = await callOpenAIFallback(body);
          if (fallback?.ok) {
            console.log("[proxy] OpenAI fallback succeeded");
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

      // Reset auth failure counter on success
      _consecutiveAuthFailures = 0;

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

                  // Message stop
                  else if (event.type === "message_delta" && event.delta?.stop_reason) {
                    const stopReason = event.delta.stop_reason;
                    const finishReason = stopReason === "tool_use" ? "tool_calls" : "stop";
                    emit(baseChunk({ choices: [{ index: 0, delta: {}, finish_reason: finishReason }] }));
                    controller.enqueue(enc.encode("data: [DONE]\n\n"));
                  }

                  else if (event.type === "message_stop") {
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
      const openAIResponse = convertAnthropicToOpenAI(anthropicResponse, originalModel);
      return Response.json(openAIResponse);
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
║           gpt-4o-mini → claude-haiku                 ║
║  Fallback: OpenAI direct (if OPENAI_API_KEY set)     ║
╚══════════════════════════════════════════════════════╝
`);
