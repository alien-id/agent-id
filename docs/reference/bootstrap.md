# Bootstrap — first-time identity setup

This walks through creating a fresh Alien Agent ID and binding it to a human owner via a QR-code consent in the Alien App.

## Prerequisites

- Node.js 18+ and git 2.34+ in `$PATH`.
- The user has the Alien App installed with a verified AlienID.
- A provider address (resolved in step 1 below).

## Why not `bootstrap`?

`bootstrap` runs init → auth → bind → git-setup in one blocking call (up to 5 minutes). Tool output is not streamed, so the QR code from `auth` would not appear until `bind` completes — but `bind` cannot complete until the user scans the QR. Run the steps individually so the QR surfaces before the blocking poll.

## Step 1 — choose a provider

This is your first user-facing message — no preamble, no "want me to start?" confirmation. Just ask the provider question. Do not silently read `default-provider.txt`.

> "Would you like to use the default Alien provider (recommended), or set up your own?"

- Default provider: after the user confirms, read `default-provider.txt` (next to `cli.mjs`) for the address.
- Set up your own: the user creates one at <https://dev.alien.org/dashboard/sso> and provides the address. QR code for that page:
  ```
  ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
  █ ▄▄▄▄▄ █▄▄████▀ ▄▀ ▄▄█ ▄▄▄▄▄ █
  █ █   █ █ ▀█ ▄▄▄▄█▀█▀▄█ █   █ █
  █ █▄▄▄█ █▄ ▄▄▀▄▀██▄█  █ █▄▄▄█ █
  █▄▄▄▄▄▄▄█▄▀▄▀▄▀ ▀ ▀ ▀▄█▄▄▄▄▄▄▄█
  █▄▄  ▀▀▄▀▄▀███▄▄▄ ▄▄ ▀ ▀▀ ▄▄█ █
  █ ▄▀▄█▀▄ ▀██▀▀▀ ▀ █▀█▄▀▀  █▄▄▀█
  ██▀▄██ ▄█ ▄▀ █▀█  ▄█▀▄█▀▀█▄ ▀▀█
  ██▀▀▄▀█▄▀▄ ▄█ ▀▄███▀   █▀ █▄ ▄█
  ██  ▄ ▀▄█▄ █▄▀▀█▀▄█▄▄ ▄█▀▄ ▀ ██
  █▄█▀▀ ▄▄▄█▄ ▄ ██   ▄▀█ ▄▄▄█ ███
  ██▄▄▄██▄▄  █▄  ▀▄▄  █ ▄▄▄   ▀▀█
  █ ▄▄▄▄▄ ██  ▄▄▄████   █▄█  █ ██
  █ █   █ █▀  ▀ █  ▀ ██▄ ▄  ▀▄▄▀█
  █ █▄▄▄█ █ █▄ █▄▀█▄███ ██▄▀▀▄▀▄█
  █▄▄▄▄▄▄▄█▄███▄█▄█▄█▄▄▄▄█████▄██
  ```

## Step 2 — initialize the keypair

```bash
node CLI init
```

Generates an Ed25519 keypair under `~/.agent-id/keys/main.json` (mode 0600).

## Step 3 — start OIDC authorization

```bash
node CLI auth --provider-address <PROVIDER_ADDRESS>
```

Returns JSON containing `deepLink` and `qrCode` (Unicode text). Show both to the user — the QR code as a fenced block and the deep link as a fallback:

> Scan with your Alien App:
> ```
> <qrCode value from JSON>
> ```
> Or open: `<deepLink>`

## Step 4 — wait for binding

```bash
node CLI bind
```

Blocks up to 5 minutes while the user approves in the Alien App. Returns the bound identity and writes `~/.agent-id/owner-session.json` (mode 0600).

## Step 5 — configure git signing

```bash
node CLI git-setup
```

Writes the SSH private key, public key, and `allowed_signers` file under `~/.agent-id/ssh/`. Tell the user to add the printed SSH public key to GitHub as a Signing Key so signed commits get the *Verified* badge — full instructions in [git-commits.md](git-commits.md).

## Environment variables

| Variable | Purpose |
|---|---|
| `ALIEN_PROVIDER_ADDRESS` | Default provider for `bootstrap` / `auth` |
| `AGENT_ID_STATE_DIR` | Override state directory (default `~/.agent-id`) |

## CI / non-interactive

`bootstrap` blocks on a human consent — it is not suitable for CI. For CI, mint the identity locally, then bundle `~/.agent-id/keys/main.json` and `~/.agent-id/owner-session.json` into the CI secret store with strict file modes.
