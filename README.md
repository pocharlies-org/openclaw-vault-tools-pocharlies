# openclaw-vault-tools-pocharlies

OpenClaw `vault-tools` plugin for safe HashiCorp Vault KV v2 inspection, guarded writes, and ExternalSecret diagnostics.

## Tools

- `vault_status`
- `vault_list_paths`
- `vault_secret_metadata`
- `vault_secret_keys`
- `vault_secret_read`
- `vault_secret_write`
- `vault_external_secret_status`
- `vault_render_externalsecret`
- `vault_map_consumers`
- `vault_capabilities`

## Safety Defaults

- Metadata/listing tools never return secret values.
- `vault_secret_read` redacts values unless `reveal=true` and `confirmation="REVEAL_SECRET_VALUES"`.
- `vault_secret_write` defaults to `dry_run=true`; real writes require `dry_run=false` and `confirmation="WRITE_VAULT_SECRET"`.
- There are no delete, undelete, metadata-delete, or destroy tools in v1.
- Tool errors sanitize token-looking strings.

## OpenClaw Config

Kubernetes:

```json
{
  "enabled": true,
  "config": {
    "vaultAddr": "http://vault.vault.svc.cluster.local:8200",
    "authMode": "kubernetes",
    "kubernetesMountPath": "kubernetes",
    "kubernetesRole": "openclaw-vault-tools",
    "mount": "secret",
    "kubectlBin": "/usr/local/bin/kubectl",
    "defaultNamespace": "openclaw-qwen36"
  }
}
```

Sauvage:

```json
{
  "enabled": true,
  "config": {
    "vaultAddr": "http://10.43.220.108:8200",
    "authMode": "token",
    "tokenFile": "/home/ubuntu/.openclaw/credentials/vault-tools.token",
    "mount": "secret",
    "kubectlBin": "/usr/local/bin/kubectl"
  }
}
```

## Vault Bootstrap

The policy/role bootstrap requires a Vault admin token outside this repo:

```bash
VAULT_ADDR=http://vault.vault.svc.cluster.local:8200 \
VAULT_TOKEN=... \
deploy/vault/bootstrap-vault-tools.sh
```

The script installs policy `openclaw-vault-tools` and Kubernetes auth role `openclaw-vault-tools` without printing the admin token.

For Sauvage, create a limited renewable token with the same policy and write only the token value to:

```text
/home/ubuntu/.openclaw/credentials/vault-tools.token
```

The file must be owned by `ubuntu` and have mode `0600`.

## Tests

```bash
npm test
```
