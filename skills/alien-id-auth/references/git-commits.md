# Signed git commits

## Make a signed commit

```bash
node CLI git-commit --message "feat: implement auth flow"
```

The result is a commit that is:

1. SSH-signed with the agent's Ed25519 key.
2. Tagged with trailers linking to the agent identity and human owner.
3. Logged in the hash-chained audit trail at `~/.agent-id/audit/operations.jsonl`.
4. Proof-bundled as a git note for external verification.

Push the commit and its proof note in one step:

```bash
node CLI git-commit --message "feat: implement auth flow" --push
```

The `--push` flag pushes the commit and handles note-ref merging. The default remote is `origin`; override with `--remote <name>`. Allow empty commits with `--allow-empty`.

## Normal `git commit`

A plain `git commit` still works — but skips the Agent ID trailers, proof note, and Ed25519 signing. Use `git-commit` whenever provenance matters.

## Verify a commit

```bash
node CLI git-verify --commit HEAD
```

Traces the full chain: SSH signature → agent key → owner binding → SSO attestation. When the commit has a proof note, verification is fully self-contained — works without access to the agent's state directory or any external service.

## GitHub *Verified* badge

To get the *Verified* badge on GitHub for these commits, the agent's SSH public key must be registered on the GitHub account as a Signing Key (not just an authentication key).

1. The SSH public key is printed by `git-setup` and also lives at `~/.agent-id/ssh/agent-id.pub`.
2. GitHub → Settings → SSH and GPG keys → New SSH key.
3. Set Key type to *Signing Key*.

## Sign other operations

For any significant non-git action, append a signed entry to the audit trail:

```bash
node CLI sign --type TOOL_CALL --action "bash.exec"        --payload '{"command":"deploy"}'
node CLI sign --type API_CALL  --action "github.create-pr" --payload '{"repo":"foo/bar"}'
```

Verify the entire state chain:

```bash
node CLI verify
```

Export a proof bundle for external use:

```bash
node CLI export-proof
```
