---
name: openclaw-vault
description: Use OpenClaw vault-tools safely for HashiCorp Vault KV v2 metadata, redacted reads, guarded writes, and ExternalSecret diagnostics.
---

# OpenClaw Vault

Use the `vault-tools` OpenClaw plugin when a user asks OpenClaw to inspect, map, or update HashiCorp Vault-backed secrets.

## Safety Rules

- Prefer metadata tools first: `vault_status`, `vault_list_paths`, `vault_secret_metadata`, and `vault_secret_keys`.
- Treat `vault_secret_read` as sensitive. By default it redacts values and returns only type/length/key structure.
- Reveal secret values only when the user explicitly asks for the values and the call includes `reveal=true` plus `confirmation="REVEAL_SECRET_VALUES"`.
- Never paste Vault tokens or secret values into final logs, deployment summaries, ticket comments, or public chat.
- Use `vault_secret_write` with its default `dry_run=true` before any real write.
- Real writes require `dry_run=false` and `confirmation="WRITE_VAULT_SECRET"`.
- Do not attempt delete, undelete, destroy, or metadata deletion. Those operations are intentionally absent in v1.
- For Kubernetes consumers, prefer `vault_external_secret_status`, `vault_render_externalsecret`, and `vault_map_consumers`; these do not read Kubernetes Secret values.

## Typical Workflow

1. Run `vault_status`.
2. Run `vault_list_paths` on a narrow prefix.
3. Run `vault_secret_metadata` or `vault_secret_keys` on the selected path.
4. For application wiring, render an ExternalSecret with `vault_render_externalsecret` and check existing stores with `vault_external_secret_status`.
5. For writes, dry-run first and include only synthetic or user-provided values in the tool input.
6. Confirm the resulting ExternalSecret/consumer status; do not echo the secret value back.

## Auth Expectations

- Kubernetes OpenClaw uses Vault Kubernetes auth role `openclaw-vault-tools` bound to ServiceAccount `openclaw-qwen36-openclaw` in namespace `openclaw-qwen36`.
- Sauvage uses a limited Vault token file at `/home/ubuntu/.openclaw/credentials/vault-tools.token`.
- If auth fails, report that Vault auth/bootstrap is missing rather than asking the user to paste tokens into chat.
