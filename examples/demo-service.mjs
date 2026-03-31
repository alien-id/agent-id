#!/usr/bin/env node

// Alien Agent ID — Demo Service
// A zero-dependency HTTP service that authenticates AI agents via Agent ID tokens.
// Start: node demo-service.mjs [--port 3141]
// Test:  node cli.mjs auth-header --raw | xargs -I{} curl -H {} http://localhost:3141/api/whoami

import http from "node:http";
import { verifyAgentToken } from "../lib.mjs";

const PORT = parseInt(process.argv.find((_, i, a) => a[i - 1] === "--port") || process.env.PORT || "3141", 10);

// Track known agents (in-memory for demo)
const knownAgents = new Map();

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj, null, 2) + "\n";
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Authorization, Content-Type",
  });
  res.end(body);
}

function authenticate(req) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("AgentID ")) {
    return { ok: false, error: "Missing header: Authorization: AgentID <token>" };
  }
  const token = auth.slice(8).trim();
  const result = verifyAgentToken(token);
  if (result.ok) {
    // Track agent
    const agent = knownAgents.get(result.fingerprint) || { firstSeen: new Date().toISOString(), requests: 0 };
    agent.requests++;
    agent.lastSeen = new Date().toISOString();
    agent.owner = result.owner;
    knownAgents.set(result.fingerprint, agent);
  }
  return result;
}

async function readBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  // CORS preflight
  if (req.method === "OPTIONS") {
    res.writeHead(204, {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Authorization, Content-Type",
    });
    res.end();
    return;
  }

  // ─── Public endpoints ───────────────────────────────────────────────
  if (url.pathname === "/" && req.method === "GET") {
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end(landingPageHtml());
    return;
  }

  if (url.pathname === "/api/status" && req.method === "GET") {
    sendJson(res, 200, {
      ok: true,
      service: "Alien Agent ID Demo Service",
      version: "1.0.0",
      agentsKnown: knownAgents.size,
      uptime: Math.round(process.uptime()),
    });
    return;
  }

  // ─── Protected endpoints ────────────────────────────────────────────
  const agent = authenticate(req);
  if (!agent.ok) {
    sendJson(res, 401, { ok: false, error: agent.error });
    return;
  }

  const agentInfo = knownAgents.get(agent.fingerprint);

  if (url.pathname === "/api/whoami" && req.method === "GET") {
    sendJson(res, 200, {
      ok: true,
      agent: {
        fingerprint: agent.fingerprint,
        owner: agent.owner,
        firstSeen: agentInfo?.firstSeen,
        requests: agentInfo?.requests,
        authenticatedAt: new Date().toISOString(),
      },
      message: `Hello, agent ${agent.fingerprint.slice(0, 16)}! Your identity is verified.`,
    });
    return;
  }

  if (url.pathname === "/api/protected" && req.method === "GET") {
    sendJson(res, 200, {
      ok: true,
      secret: "The Alien Network sees all, knows all, trusts only the verified.",
      accessGrantedTo: agent.fingerprint.slice(0, 16) + "...",
      owner: agent.owner,
      timestamp: new Date().toISOString(),
    });
    return;
  }

  if (url.pathname === "/api/echo" && req.method === "POST") {
    const body = await readBody(req);
    sendJson(res, 200, {
      ok: true,
      echo: body,
      agent: agent.fingerprint.slice(0, 16) + "...",
    });
    return;
  }

  if (url.pathname === "/api/agents" && req.method === "GET") {
    const agents = [];
    for (const [fp, info] of knownAgents) {
      agents.push({
        fingerprint: fp.slice(0, 16) + "...",
        owner: info.owner,
        firstSeen: info.firstSeen,
        lastSeen: info.lastSeen,
        requests: info.requests,
      });
    }
    sendJson(res, 200, { ok: true, agents });
    return;
  }

  sendJson(res, 404, { ok: false, error: "Not found" });
});

server.listen(PORT, () => {
  const lines = [
    "",
    "  Alien Agent ID — Demo Service",
    `  Listening on http://localhost:${PORT}`,
    "",
    "  Public endpoints:",
    "    GET  /             Landing page",
    "    GET  /api/status   Service status",
    "",
    "  Protected endpoints (require Authorization: AgentID <token>):",
    "    GET  /api/whoami     Agent identity info",
    "    GET  /api/protected  Access secret data",
    "    POST /api/echo       Echo request body",
    "    GET  /api/agents     List all known agents",
    "",
    "  Quick test:",
    `    node cli.mjs auth-header --raw | xargs -I{} curl -H {} http://localhost:${PORT}/api/whoami`,
    "",
  ];
  for (const line of lines) console.log(line);
});

function landingPageHtml() {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Alien Agent ID — Demo Service</title>
  <style>
    :root { color-scheme: light; --bg: #f5f7fb; --card: #fff; --text: #14213d; --muted: #51627a; --accent: #009fb7; --border: #d7deea; }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: "IBM Plex Sans", "Segoe UI", system-ui, sans-serif; background: var(--bg); color: var(--text); }
    .wrap { min-height: 100vh; display: grid; place-items: center; padding: 28px; }
    .card { width: min(720px, 100%); background: var(--card); border: 1px solid var(--border); border-radius: 18px; box-shadow: 0 8px 24px rgba(16,24,40,0.08); padding: 32px; }
    .eyebrow { color: var(--accent); font-weight: 700; letter-spacing: 0.06em; text-transform: uppercase; font-size: 12px; margin-bottom: 8px; }
    h1 { margin: 0 0 12px; font-size: 28px; }
    p { color: var(--muted); line-height: 1.6; margin: 0 0 16px; }
    h2 { font-size: 18px; margin: 24px 0 8px; }
    pre { background: #f0f3f8; border: 1px solid var(--border); border-radius: 10px; padding: 14px 16px; font-size: 13px; overflow-x: auto; line-height: 1.5; }
    code { font-family: "JetBrains Mono", "Fira Code", monospace; }
    .endpoint { display: grid; grid-template-columns: 70px 1fr; gap: 4px 12px; font-size: 14px; margin-bottom: 6px; }
    .method { font-weight: 700; color: var(--accent); font-family: monospace; }
    .path { font-family: monospace; }
    .tag { display: inline-block; font-size: 11px; padding: 2px 8px; border-radius: 99px; font-weight: 600; }
    .tag-public { background: #e6f9f0; color: #0a7c42; }
    .tag-auth { background: #fff3e0; color: #b8651a; }
    a { color: var(--accent); }
  </style>
</head>
<body>
  <main class="wrap">
    <section class="card">
      <div class="eyebrow">Demo Service</div>
      <h1>Alien Agent ID</h1>
      <p>This service authenticates AI agents using cryptographic Agent ID tokens. Only agents with a verified identity linked to a human owner can access protected endpoints.</p>

      <h2>Endpoints</h2>
      <div class="endpoint"><span class="method">GET</span> <span class="path">/api/status</span> <span class="tag tag-public">public</span></div>
      <div class="endpoint"><span class="method">GET</span> <span class="path">/api/whoami</span> <span class="tag tag-auth">auth required</span></div>
      <div class="endpoint"><span class="method">GET</span> <span class="path">/api/protected</span> <span class="tag tag-auth">auth required</span></div>
      <div class="endpoint"><span class="method">POST</span> <span class="path">/api/echo</span> <span class="tag tag-auth">auth required</span></div>
      <div class="endpoint"><span class="method">GET</span> <span class="path">/api/agents</span> <span class="tag tag-auth">auth required</span></div>

      <h2>Authentication</h2>
      <p>Include a signed Agent ID token in the Authorization header:</p>
      <pre><code>Authorization: AgentID &lt;token&gt;</code></pre>
      <p>Generate a token using the agent-id CLI:</p>
      <pre><code># Get token as JSON
node cli.mjs auth-header

# Use directly with curl
curl -H "$(node cli.mjs auth-header --raw)" http://localhost:${PORT}/api/whoami</code></pre>

      <h2>Trust Chain</h2>
      <p>Every request is verified through a cryptographic provenance chain:</p>
      <pre><code>HTTP request
  \u2192 Agent ID token (Ed25519 signature)
    \u2192 Agent public key (fingerprint match)
      \u2192 Owner binding (agent \u2194 human link)
        \u2192 SSO attestation (Alien Network)</code></pre>
    </section>
  </main>
</body>
</html>`;
}
