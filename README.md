# Claude Code's Entire Source Code Got Leaked via a Sourcemap in npm, Let's Talk About It

> **PS:** This breakdown is also available on [this blog](https://kuber.studio/blog/AI/Claude-Code's-Entire-Source-Code-Got-Leaked-via-a-Sourcemap-in-npm,-Let's-Talk-About-it) with a better reading experience and UX :)

> **Note:** There's a non-zero chance this repo might be taken down. If you want to play around with it later or archive it yourself, feel free to **fork it** and bookmark the external blog link!

---

## 🧐 How Did This Even Happen?

When you publish a JavaScript/TypeScript package to npm, the build toolchain often generates **source map files** (`.map` files). These files bridge minified production code and the original source for debugging.

The catch? **Source maps contain the original source code** embedded as strings inside a JSON file under the `sourcesContent` key.

```json
{
  "version": 3,
  "sources": ["../src/main.tsx", "../src/tools/BashTool.ts", "..."],
  "sourcesContent": ["// The ENTIRE original source code of each file", "..."],
  "mappings": "AAAA,SAAS,OAAO..."
}
```

By forgetting to add `*.map` to `.npmignore` or failing to disable source maps in production builds (Bun's default behavior), the entire raw source was shipped to the npm registry.

[![Claude Code source files exposed in npm package](assets/claude-npm-img.png)](assets/claude-npm-img.png)

---

## 🛠 Best Practices for Building AI-Powered CLI Systems

Instead of focusing on internal implementations, this section highlights **practical best practices** you can apply when building your own AI-powered CLI, agent framework, or developer tooling platform.

### 🧠 Modular Agent Architecture

- Break your system into **independent, composable tools**
- Use a shared interface (e.g. Tool base class) for consistency
- Allow dynamic tool discovery and execution
- Avoid tightly coupling logic into a single monolithic file

### 🔁 Multi-Agent Orchestration

- Separate responsibilities across agents (planner, executor, memory, etc.)
- Use a coordinator layer to manage task delegation
- Enable parallelism where possible for performance
- Keep agents stateless where feasible, and persist state externally

### 🧩 Tooling System Design

- Build tools as reusable, isolated units (filesystem, web, code execution, etc.)
- Standardise input/output schemas for reliability
- Add validation and error handling at the tool level
- Log all tool interactions for debugging and observability

### 🧠 Memory & Context Management

- Maintain both **short-term (session)** and **long-term (persistent)** memory
- Regularly prune irrelevant or outdated context
- Use summarisation to compress large histories efficiently
- Store structured memory (not just raw text)

### ⚙️ Background Processing & Automation

- Run background jobs for memory consolidation, indexing, or analytics
- Design systems that can operate asynchronously without blocking the main flow
- Use queues or schedulers for reliability

### 🛡️ Safety & Output Control

- Implement guardrails to prevent sensitive data exposure
- Filter internal system details from outputs
- Enforce structured responses where needed
- Add role-based or environment-based behaviour controls

### 🚀 Planning & Reasoning Systems

- Separate **planning** from **execution**
- Use lightweight reasoning for simple tasks and deeper planning for complex ones
- Allow fallback strategies if initial plans fail
- Track task progress and intermediate steps

### 🧪 Developer Experience (DX)

- Provide clear CLI feedback and logs
- Make debugging easy with verbose modes
- Ensure fast iteration cycles (hot reload, fast builds)
- Document tool capabilities and expected inputs clearly

### 📈 Observability & Analytics

- Track usage, errors, and performance metrics
- Log agent decisions and tool calls for transparency
- Use analytics to improve system behaviour over time

---

## 📂 Architecture & Directory Structure

```text
src/
├── main.tsx                 # CLI Entrypoint (Commander.js + React/Ink)
├── QueryEngine.ts           # Core LLM logic (~46K lines)
├── Tool.ts                  # Base tool definitions
├── tools/                   # 40+ Agent tools (Bash, Files, LSP, Web)
├── services/                # Backend (MCP, OAuth, Analytics, Dreams)
├── coordinator/             # Multi-agent orchestration (Swarm)
├── bridge/                  # IDE Integration layer
└── buddy/                   # The secret Tamagotchi system
```

---

## ⚙️ How to Use & Explore

### 📦 Prerequisites

- **[Bun Runtime](https://bun.sh)** (Highly Recommended) or Node.js v18+
- **TypeScript** installed globally

### 🚀 Getting Started

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/your-username/claude-leaked.git
    cd claude-leaked
    ```

2.  **Install Dependencies:**

    ```bash
    npm install
    ```

3.  **Build the Project:**

    ```bash
    npm run build
    ```

4.  **Run the CLI:**
    ```bash
    node dist/main.js
    ```

### 🔍 Explore with MCP

This repo includes an **MCP Server** to let you explore the source using Claude itself:

```bash
claude mcp add code-explorer -- npx -y claude-code-explorer-mcp
```

---

## 📈 SEO & Rankings

**Keywords:** `Claude Code Leak`, `Anthropic Source Code`, `AI Agent Framework`, `Claude 3.5 Sonnet CLI`, `Tengu Anthropic`, `npm sourcemap leak`, `Open Source AI Agent`.

---

Earlier today (March 31st, 2026)

This repository explores how a full AI-powered coding CLI can be structured, and uses that as a foundation to break down architecture patterns, system design decisions, and best practices for building similar tools.

---

## 📜 Notes

This repository is intended as a technical exploration of AI system design, architecture patterns, and developer tooling concepts.

---

### 📩 Contact

Contact details removed for privacy.
