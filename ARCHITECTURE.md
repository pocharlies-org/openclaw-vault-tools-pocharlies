# ARCHITECTURE.md — openclaw-vault-tools-pocharlies

**Repo retirado.** Plugin de OpenClaw que daba a los agentes lectura y escritura (`vault_secret_write`) sobre Vault. Por orden del CTO (12-09-2026, SC-490) murió con Vault y OpenClaw; el repo quedó sin código.

## Clientes y versiones
- Ninguno activo. No es un MCP ni tiene ruta en AgentGateway. OpenClaw se retiró el 2026-09-16 (sustituido por Hermes): el consumidor ya no existe.
- Sin versiones ni etiquetas.

## Dependencias en ambos sentidos
- **Depende de:** nada (sin código).
- **Quién dependía de él:** `k8s-openclaw-qwen36-pocharlies` (submódulo, grants de las 10 herramientas `vault_*`); su retiro vive en la rama `sc498-baja-vault-tools` de ese repo.
- Sin `CONTRACTS.yaml`.

## Stack
- Ninguno. Antes: plugin Node de OpenClaw (`index.js`, `lib/`, `openclaw.plugin.json`) y un role de Kubernetes en Vault, eliminados.

## Componentes compartidos
- Ninguno. No reutilizar este diseño: un acceso de escritura a los secretos del clúster desde agentes no se reescribe contra 1Password (volvería a exponer el almacén); sería una épica propia con su diseño de permisos.

## Cómo se construye
- No se construye. El repo contiene solo `README.md` y los workflows de la org.

## Tests
- No hay.

## CI/CD y despliegue
- `duplicados.yml` y `pr-review.yml`. Sin imagen ni ArgoCD. Tronco: `main`.

## Decisiones y trampas
- El README advierte de **no fusionar** el PR de vaciado hasta que se entregue la medición del árbol `aurora/` (SC-503); si el repo ya está vaciado en el tronco, el aviso es histórico.
- Propuesta SC-1430 (no ejecutar en esa épica): archivar el repo cuando SC-490 cierre su fase 6.

## Reutilización
- Para acceso a secretos desde agentes: la ruta `/1password` del gateway y el flujo vault/external-secrets del clúster, no este plugin. Búsquedas: lectura del README y de los workflows del repo; nota sobre la ruta `/1password` en `k8s-agentgateway-pocharlies`.
