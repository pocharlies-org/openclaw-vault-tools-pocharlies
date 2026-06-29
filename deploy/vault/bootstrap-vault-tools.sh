#!/usr/bin/env bash
set -euo pipefail

# Requires an existing Vault admin/break-glass token in VAULT_TOKEN.
# This script intentionally never prints VAULT_TOKEN or any secret values.

ROLE_NAME="${ROLE_NAME:-openclaw-vault-tools}"
POLICY_NAME="${POLICY_NAME:-openclaw-vault-tools}"
K8S_AUTH_MOUNT="${K8S_AUTH_MOUNT:-kubernetes}"
K8S_NAMESPACE="${K8S_NAMESPACE:-openclaw-qwen36}"
K8S_SERVICE_ACCOUNT="${K8S_SERVICE_ACCOUNT:-openclaw-qwen36-openclaw}"
POLICY_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/openclaw-vault-tools-policy.hcl"

if [ -z "${VAULT_ADDR:-}" ]; then
  echo "VAULT_ADDR is required" >&2
  exit 2
fi
if [ -z "${VAULT_TOKEN:-}" ]; then
  echo "VAULT_TOKEN is required" >&2
  exit 2
fi

vault policy write "${POLICY_NAME}" "${POLICY_FILE}" >/dev/null
vault write "auth/${K8S_AUTH_MOUNT}/role/${ROLE_NAME}" \
  bound_service_account_names="${K8S_SERVICE_ACCOUNT}" \
  bound_service_account_namespaces="${K8S_NAMESPACE}" \
  policies="${POLICY_NAME}" \
  ttl="1h" >/dev/null

echo "Vault policy and Kubernetes auth role installed: ${POLICY_NAME} / ${ROLE_NAME}"
echo "For Sauvage, create a limited token separately with:"
echo "  vault token create -policy=${POLICY_NAME} -period=24h -renewable=true"
echo "Write only the token value to /home/ubuntu/.openclaw/credentials/vault-tools.token with mode 0600."
