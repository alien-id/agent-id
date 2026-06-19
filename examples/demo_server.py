#!/usr/bin/env python3
"""Interactive demo server for the Arcade × Alien Agent ID integration.

Serves examples/demo.html and exposes small JSON endpoints that run REAL Arcade
tools live, authenticated by the self-hosted agent-id-oauth broker. Clicking a
button in the page hits one of these endpoints, which:

  load the Arcade toolkit -> read the tool's auth requirement -> get a token from
  the broker (vault) -> inject ToolContext -> run via Arcade's own ToolExecutor.

Run it with the venv that has the Arcade toolkits installed, e.g.:

  ~/.agents/skills/alien-agent-id/.venv/bin/python examples/demo_server.py
  # then open http://127.0.0.1:8000

Endpoints:
  GET /                          -> demo.html
  GET /api/catalog               -> {total, services:{module:count}}
  GET /api/run?toolkit=&tool=&input=  -> run an Arcade tool, return its output
  GET /api/discord?path=/users/@me/guilds -> brokered Discord REST call
"""

import asyncio
import importlib
import json
import os
import subprocess
import sys
import urllib.request
import warnings
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

warnings.filterwarnings("ignore")

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import arcade_bridge as ab  # reuse load_tool, DEFAULT_CLI, PROVIDER_ALIASES

from arcade_core.executor import ToolExecutor
from arcade_core.schema import ToolAuthorizationContext, ToolContext

TOOLKITS = [
    "arcade_gmail", "arcade_google_calendar", "arcade_google_docs", "arcade_google_drive",
    "arcade_github", "arcade_slack", "arcade_notion_toolkit", "arcade_linear", "arcade_x",
    "arcade_spotify", "arcade_zoom", "arcade_asana", "arcade_dropbox", "arcade_hubspot",
    "arcade_web", "arcade_search", "arcade_code_sandbox",
]

_catalog_cache = None


def build_catalog():
    global _catalog_cache
    if _catalog_cache:
        return _catalog_cache
    from arcade_core.catalog import ToolCatalog
    cat = ToolCatalog()
    per = {}
    for m in TOOLKITS:
        try:
            before = len(list(cat))
            cat.add_module(importlib.import_module(m))
            per[m] = len(list(cat)) - before
        except Exception:
            per[m] = 0
    _catalog_cache = {"total": len(list(cat)), "services": per}
    return _catalog_cache


def get_token(provider, scopes):
    """Call the broker CLI; return (token, None) or (None, error_dict)."""
    cmd = ["node", ab.DEFAULT_CLI, "token", "--provider", provider]
    if scopes:
        cmd += ["--scopes", " ".join(scopes)]
    p = subprocess.run(cmd, capture_output=True, text=True)
    try:
        data = json.loads(p.stdout or "{}")
    except json.JSONDecodeError:
        return None, {"error": (p.stdout or p.stderr or "broker error").strip()}
    if not data.get("ok"):
        return None, data
    return data["access_token"], None


async def run_tool(toolkit, tool, inp):
    mt = ab.load_tool(toolkit, tool)
    info = {"tool": mt.name, "toolkit": toolkit}
    ctx = ToolContext()
    reqs = mt.definition.requirements
    auth = getattr(reqs, "authorization", None) if reqs else None
    if auth is not None:
        provider = ab.PROVIDER_ALIASES.get(auth.provider_id, auth.provider_id)
        oauth2 = getattr(auth, "oauth2", None)
        scopes = (getattr(oauth2, "scopes", None) if oauth2 else None) or getattr(auth, "scopes", None) or []
        info["provider"] = provider
        info["scopes"] = scopes
        token, err = get_token(provider, scopes)
        if err:
            return {"ok": False, "info": info, **err}
        ctx.authorization = ToolAuthorizationContext(token=token)
    out = await ToolExecutor.run(mt.tool, mt.definition, mt.input_model, mt.output_model, ctx, **inp)
    res = json.loads(out.model_dump_json())
    return {"ok": res.get("error") is None, "value": res.get("value"), "error": res.get("error"), "info": info}


class Handler(BaseHTTPRequestHandler):
    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        try:
            if u.path in ("/", "/index.html"):
                html = open(os.path.join(HERE, "demo.html"), "rb").read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(html)))
                self.end_headers()
                self.wfile.write(html)
                return
            if u.path == "/api/catalog":
                self._json(build_catalog())
                return
            if u.path == "/api/run":
                tk = q.get("toolkit", [""])[0]
                tool = q.get("tool", [""])[0]
                inp = json.loads(q.get("input", ["{}"])[0] or "{}")
                self._json(asyncio.run(run_tool(tk, tool, inp)))
                return
            if u.path == "/api/discord":
                path = q.get("path", ["/users/@me/guilds"])[0]
                token, err = get_token("discord", ["identify", "guilds"])
                if err:
                    self._json({"ok": False, **err})
                    return
                req = urllib.request.Request(
                    "https://discord.com/api" + path,
                    headers={"Authorization": f"Bearer {token}", "User-Agent": "agent-id-demo/1.0"},
                )
                with urllib.request.urlopen(req) as r:
                    self._json({"ok": True, "value": json.load(r)})
                return
            self._json({"ok": False, "error": {"message": "not found"}}, 404)
        except Exception as e:  # surface errors as JSON so the page can show them
            self._json({"ok": False, "error": {"message": str(e)}})

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    print(f"Arcade × Alien Agent ID demo  ->  http://127.0.0.1:{port}")
    print("(serving examples/demo.html; endpoints run real Arcade tools via the broker)")
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
