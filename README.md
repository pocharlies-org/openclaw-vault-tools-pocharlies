# openclaw-vault-tools-pocharlies — RETIRADO

**Ruling del CTO (12-09-2026, SC-490):** este plugin muere con Vault. Da a los
agentes superficie de lectura *y escritura* (`vault_secret_write`) sobre el
almacén de las credenciales del clúster; reescribirlo contra 1Password volvería
a exponer el almacén. Si algún día se necesita un equivalente, será una épica
propia con su propio diseño de permisos — no una traducción de este código.

El retiro del consumidor (submodule, grants de las 10 herramientas `vault_*`,
`VAULT_ADDR` de los Deployments) vive en
`k8s-openclaw-qwen36-pocharlies`, rama `sc498-baja-vault-tools`.

Este PR deja el repo vacío de código: fuera `index.js`, `lib/`, `test/`,
`openclaw.plugin.json`, el skill `openclaw-vault` y `deploy/vault/` (el
bootstrap del role Kubernetes `openclaw-vault-tools` y su policy HCL). El role
y la policy viven dentro de Vault y mueren con él en la fase 6 de SC-490; no
hay nada que desprovisionar en Git.

## Advertencia de merge

**NO fusionar hasta que la medición del árbol `aurora/` (SC-503,
`_ops/vault-to-1password/5bis/investigacion-aurora-vaulttools.md`) esté
entregada**: el backend de secretos de runtime de Aurora solo admite Vault, y
este plugin era la única vía sin token para medir ese árbol.
