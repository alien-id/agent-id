#!/usr/bin/env node

// Alien Agent ID — OAuth broker plugin CLI.
//
// Self-hosted OAuth 2.0 token brokering keyed off the agent's identity. Runs the
// Authorization Code (+ PKCE) flow with your own OAuth apps, stores access/refresh
// tokens in the encrypted vault (agent-id-vault), and refreshes them on demand —
// so downstream tools get a valid bearer token without a hosted auth engine.
//
// Subcommands: register, login, complete, token, list, logout.

import { stderr, runCli } from "../../agent-id-core/lib/cli-runtime.mjs";
import {
  cmdRegister,
  cmdLogin,
  cmdComplete,
  cmdToken,
  cmdList,
  cmdLogout,
  SUPPORTED_PROVIDERS,
} from "../lib/oauth.mjs";

function printHelp() {
  stderr(
    [
      "agent-id-oauth — self-hosted OAuth 2.0 token broker",
      "",
      "Subcommands:",
      "  register --provider <P> --client-id <ID> [--client-secret S | --client-secret-env V]",
      "           [--redirect-uri URI] [--port N]",
      "  login    --provider <P> --scopes \"<a b c>\"",
      "  complete --provider <P> (--serve [--timeout-sec N] | --callback-url <URL> | --code <CODE>)",
      "  token    --provider <P> [--scopes \"<a b c>\"] [--raw]",
      "  list",
      "  logout   --provider <P>",
      "",
      `Built-in providers: ${SUPPORTED_PROVIDERS.join(", ")}`,
      "Generic provider (not in catalog): pass --authorize-url, --token-url, and",
      "  optionally --scope-separator, --scope-param, --token-auth <body|basic>, --pkce/--no-pkce.",
      "",
      "Common flags: --state-dir <path> (defaults to AGENT_ID_STATE_DIR or ~/.agent-id)",
    ].join("\n"),
  );
}

const commands = {
  register: cmdRegister,
  login: cmdLogin,
  complete: cmdComplete,
  token: cmdToken,
  list: cmdList,
  logout: cmdLogout,
};

runCli({ commands, printHelp });
