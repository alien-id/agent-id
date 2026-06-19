#!/usr/bin/env python3
"""Run Arcade's open-source tools with auth brokered by the Alien Agent ID vault.

This REUSES Arcade's tool implementations (the arcade-* toolkit packages — Gmail,
Slack, GitHub, … thousands of tools) but REPLACES Arcade's hosted auth engine: the
access token is fetched from the agent-id-oauth broker (`token`), which stores/
refreshes tokens in the agent's encrypted vault. No Arcade Cloud, no ARCADE_API_KEY —
just the OSS tools plus your own OAuth apps.

Architecture (the heavy lifting stays in Arcade's code):
  ToolCatalog.add_module(toolkit)            -> load the real tool implementations
  tool.definition.requirements.authorization -> provider_id + required scopes
  agent-id-oauth token --provider … --scopes … -> a valid access token from the vault
  ToolContext(authorization=ToolAuthorizationContext(token=…)) -> inject our token
  ToolExecutor.run(...)                      -> Arcade validates input, injects ctx, runs

Usage:
  python3 arcade_bridge.py --toolkit arcade_gmail --tool ListEmails \
      --input '{"n_emails": 5}'

  # provider/scopes are normally read from the tool's own auth requirement;
  # override only for tools outside the catalog or to widen scopes:
  python3 arcade_bridge.py --toolkit arcade_slack --tool SendMessage \
      --input '{...}' --provider slack --scopes "chat:write"

Prereqs:
  pip install arcade-mcp <toolkit>     (e.g. arcade-gmail)
  node ../plugins/agent-id-oauth/bin/cli.mjs register --provider google --client-id … --client-secret-env …
  node ../plugins/agent-id-oauth/bin/cli.mjs login    --provider google --scopes "…"
  node ../plugins/agent-id-oauth/bin/cli.mjs complete  --provider google --serve
"""

import argparse
import asyncio
import importlib
import json
import os
import subprocess
import sys

# The agent-id-oauth broker CLI, relative to this examples/ file.
DEFAULT_CLI = os.path.normpath(
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..",
        "plugins",
        "agent-id-oauth",
        "bin",
        "cli.mjs",
    )
)

# Arcade provider_ids mostly match the broker's provider names; map the few that differ.
PROVIDER_ALIASES = {
    "arcade-google": "google",
    "arcade-github": "github",
    "arcade-slack": "slack",
    "arcade-microsoft": "microsoft",
    "arcade-x": "x",
}


def eprint(*a):
    print(*a, file=sys.stderr)


def broker_token(cli_path, state_dir, provider, scopes):
    """Fetch a valid access token from the agent-id-oauth broker."""
    cmd = ["node", cli_path, "token", "--provider", provider]
    if scopes:
        cmd += ["--scopes", " ".join(scopes)]
    if state_dir:
        cmd += ["--state-dir", state_dir]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        raise SystemExit(f"Broker returned non-JSON output:\n{proc.stdout}\n{proc.stderr}")
    if not data.get("ok"):
        if data.get("needs_consent"):
            raise SystemExit(
                "Missing scope(s) for "
                f"{provider}: {data.get('missing_scopes')}.\n{data.get('action')}"
            )
        raise SystemExit(f"Broker error: {data.get('error', proc.stderr or 'unknown')}")
    return data["access_token"]


def load_tool(toolkit_module, tool_name):
    """Load Arcade's catalog with the given toolkit and return the MaterializedTool."""
    from arcade_core.catalog import ToolCatalog  # imported lazily so --help works w/o arcade

    module = importlib.import_module(toolkit_module)
    catalog = ToolCatalog()
    catalog.add_module(module)
    for mt in catalog:  # ToolCatalog is iterable over MaterializedTool
        if mt.name == tool_name or mt.name.endswith(f".{tool_name}"):
            return mt
    available = ", ".join(sorted(mt.name for mt in catalog))
    raise SystemExit(f"Tool '{tool_name}' not found in {toolkit_module}.\nAvailable: {available}")


async def run(args):
    from arcade_core.executor import ToolExecutor
    from arcade_core.schema import ToolAuthorizationContext, ToolContext

    mt = load_tool(args.toolkit, args.tool)

    ctx = ToolContext()
    auth = getattr(mt.definition.requirements, "authorization", None) if mt.definition.requirements else None
    if auth is not None:
        provider = args.provider or PROVIDER_ALIASES.get(auth.provider_id, auth.provider_id)
        # scopes live on auth.oauth2.scopes (newer toolkits) or auth.scopes (older).
        oauth2 = getattr(auth, "oauth2", None)
        req_scopes = (getattr(oauth2, "scopes", None) if oauth2 else None) or getattr(auth, "scopes", None) or []
        scopes = args.scopes.split() if args.scopes else req_scopes
        if not provider:
            raise SystemExit("Tool requires auth but no provider_id; pass --provider.")
        eprint(f"[bridge] brokering token for provider={provider} scopes={scopes}")
        token = broker_token(args.cli, args.state_dir, provider, scopes)
        ctx.authorization = ToolAuthorizationContext(token=token)

    tool_input = json.loads(args.input) if args.input else {}

    # Hand off to Arcade's own executor: it validates input, injects the context
    # into the tool's context parameter, runs the function, and formats output.
    output = await ToolExecutor.run(
        mt.tool,
        mt.definition,
        mt.input_model,
        mt.output_model,
        ctx,
        **tool_input,
    )
    try:
        print(output.model_dump_json(indent=2))
    except AttributeError:
        print(json.dumps(output, default=str, indent=2))


def main():
    p = argparse.ArgumentParser(description="Run Arcade OSS tools with Alien Agent ID-brokered auth.")
    p.add_argument("--toolkit", required=True, help="Python module of the toolkit, e.g. arcade_gmail")
    p.add_argument("--tool", required=True, help="Tool name, e.g. ListEmails")
    p.add_argument("--input", default="", help="Tool input as a JSON object string")
    p.add_argument("--provider", default="", help="Override broker provider (else from tool's auth requirement)")
    p.add_argument("--scopes", default="", help="Override scopes, space-separated (else from tool's auth requirement)")
    p.add_argument("--cli", default=DEFAULT_CLI, help="Path to the agent-id-oauth cli.mjs (the broker)")
    p.add_argument("--state-dir", default="", help="Agent ID state dir (default: ~/.agent-id)")
    args = p.parse_args()
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
