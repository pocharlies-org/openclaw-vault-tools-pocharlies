"use strict";

const {
  VaultClient,
  cleanObject,
  cleanString,
  kvPath,
  normalizeLogicalPath,
  normalizeMount,
  pickKeys,
  redactData,
  resolveVaultConfig,
  sanitizeError,
} = require("./lib/vault-client");
const {
  externalSecretStatus,
  mapConsumers,
  renderExternalSecret,
} = require("./lib/k8s-client");

const REVEAL_CONFIRMATION = "REVEAL_SECRET_VALUES";
const WRITE_CONFIRMATION = "WRITE_VAULT_SECRET";

const VAULT_TOOL_NAMES = [
  "vault_status",
  "vault_list_paths",
  "vault_secret_metadata",
  "vault_secret_keys",
  "vault_secret_read",
  "vault_secret_write",
  "vault_external_secret_status",
  "vault_render_externalsecret",
  "vault_map_consumers",
  "vault_capabilities",
];

function textJson(value) {
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(value, null, 2),
      },
    ],
  };
}

function compactError(error) {
  return sanitizeError(error);
}

function toolError(tool, error) {
  return textJson({ ok: false, tool, error: compactError(error) });
}

function boolParam(value, fallback) {
  if (typeof value === "boolean") return value;
  return fallback;
}

function resolveRuntime(api) {
  const cfg = cleanObject(api && api.pluginConfig);
  const vault = resolveVaultConfig(cfg);
  return {
    ...vault,
    kubectlBin: cleanString(cfg.kubectlBin) || "kubectl",
    defaultNamespace: cleanString(cfg.defaultNamespace) || "default",
  };
}

function createVaultClient(runtime) {
  return new VaultClient(runtime);
}

async function executeSafe(tool, fn) {
  try {
    return textJson({ ok: true, tool, ...(await fn()) });
  } catch (error) {
    return toolError(tool, error);
  }
}

function revealAllowed(runtime, params) {
  return runtime.allowReveal !== false && params.reveal === true && params.confirmation === REVEAL_CONFIRMATION;
}

function revealWarning(runtime, params) {
  if (params.reveal !== true) return undefined;
  if (runtime.allowReveal === false) return "Secret value reveal is disabled by plugin config.";
  if (params.confirmation !== REVEAL_CONFIRMATION) return `Secret values remain redacted. To reveal, set confirmation exactly to ${REVEAL_CONFIRMATION}.`;
  return undefined;
}

const pathParam = {
  type: "string",
  description: "KV v2 logical path under the configured mount, without /data or /metadata.",
};

const mountParam = {
  type: "string",
  description: "Optional Vault KV v2 mount. Defaults to plugin config mount, normally secret.",
};

const plugin = {
  description: "Safe HashiCorp Vault KV v2 tools for OpenClaw.",
  register(api) {
    api.registerTool({
      name: "vault_status",
      description: "Check Vault health without returning tokens or secret values.",
      parameters: {
        type: "object",
        additionalProperties: false,
        properties: {},
      },
      execute: async () => executeSafe("vault_status", async () => {
        const runtime = resolveRuntime(api);
        const client = createVaultClient(runtime);
        return { status: await client.status(), authMode: runtime.authMode, mount: runtime.mount };
      }),
    });

    api.registerTool({
      name: "vault_list_paths",
      description: "List child keys under a Vault KV v2 metadata path. Returns path names only, never secret values.",
      parameters: {
        type: "object",
        additionalProperties: false,
        properties: {
          mount: mountParam,
          path: pathParam,
        },
      },
      execute: async (_callId, params = {}) => executeSafe("vault_list_paths", async () => {
        const client = createVaultClient(resolveRuntime(api));
        return { result: await client.listPaths(params.path || "", { mount: params.mount }) };
      }),
    });

    api.registerTool({
      name: "vault_secret_metadata",
      description: "Read Vault KV v2 metadata for a secret path. Returns version/timestamp/custom metadata, never secret values.",
      parameters: {
        type: "object",
        additionalProperties: false,
        required: ["path"],
        properties: {
          mount: mountParam,
          path: pathParam,
        },
      },
      execute: async (_callId, params = {}) => executeSafe("vault_secret_metadata", async () => {
        const client = createVaultClient(resolveRuntime(api));
        return { result: await client.metadata(params.path, { mount: params.mount }) };
      }),
    });

    api.registerTool({
      name: "vault_secret_keys",
      description: "Read a Vault KV v2 secret and return only the available key names plus metadata. Values are never returned.",
      parameters: {
        type: "object",
        additionalProperties: false,
        required: ["path"],
        properties: {
          mount: mountParam,
          path: pathParam,
          version: {
            type: "integer",
            description: "Optional KV v2 version.",
          },
        },
      },
      execute: async (_callId, params = {}) => executeSafe("vault_secret_keys", async () => {
        const client = createVaultClient(resolveRuntime(api));
        const result = await client.readSecret(params.path, { mount: params.mount, version: params.version });
        return {
          mount: result.mount,
          path: result.path,
          keys: Object.keys(result.data).sort(),
          metadata: result.metadata,
        };
      }),
    });

    api.registerTool({
      name: "vault_secret_read",
      description:
        "Read a Vault KV v2 secret. Values are redacted by default; revealing values requires reveal=true and confirmation=REVEAL_SECRET_VALUES.",
      parameters: {
        type: "object",
        additionalProperties: false,
        required: ["path"],
        properties: {
          mount: mountParam,
          path: pathParam,
          keys: {
            type: "array",
            items: { type: "string" },
            description: "Optional subset of secret keys to return/redact.",
          },
          version: {
            type: "integer",
            description: "Optional KV v2 version.",
          },
          reveal: {
            type: "boolean",
            default: false,
          },
          confirmation: {
            type: "string",
            description: "Must equal REVEAL_SECRET_VALUES when reveal=true.",
          },
        },
      },
      execute: async (_callId, params = {}) => executeSafe("vault_secret_read", async () => {
        const runtime = resolveRuntime(api);
        const client = createVaultClient(runtime);
        const result = await client.readSecret(params.path, { mount: params.mount, version: params.version });
        const selected = pickKeys(result.data, params.keys);
        const reveal = revealAllowed(runtime, params);
        const warning = revealWarning(runtime, params);
        const serialized = JSON.stringify(selected);
        if (reveal && serialized.length > runtime.readValueMaxChars) {
          throw new Error(`revealed secret payload exceeds readValueMaxChars=${runtime.readValueMaxChars}`);
        }
        return {
          mount: result.mount,
          path: result.path,
          metadata: result.metadata,
          keys: Object.keys(selected).sort(),
          revealed: reveal,
          data: reveal ? selected : redactData(selected),
          ...(warning ? { warning } : {}),
        };
      }),
    });

    api.registerTool({
      name: "vault_secret_write",
      description:
        "Write a Vault KV v2 secret. Defaults to dry_run=true. Real writes require dry_run=false and confirmation=WRITE_VAULT_SECRET.",
      parameters: {
        type: "object",
        additionalProperties: false,
        required: ["path", "data"],
        properties: {
          mount: mountParam,
          path: pathParam,
          data: {
            type: "object",
            additionalProperties: true,
            description: "Secret key/value object. Values are never echoed back by this tool.",
          },
          cas: {
            type: "integer",
            description: "Optional KV v2 check-and-set version.",
          },
          dry_run: {
            type: "boolean",
            default: true,
          },
          confirmation: {
            type: "string",
            description: "Must equal WRITE_VAULT_SECRET when dry_run=false.",
          },
        },
      },
      execute: async (_callId, params = {}) => executeSafe("vault_secret_write", async () => {
        const runtime = resolveRuntime(api);
        const dryRun = boolParam(params.dry_run, true);
        const data = cleanObject(params.data);
        const mount = normalizeMount(params.mount || runtime.mount);
        const path = normalizeLogicalPath(params.path);
        const keyNames = Object.keys(data).sort();
        if (keyNames.length === 0) throw new Error("data must contain at least one key");
        if (dryRun) {
          return {
            dryRun: true,
            mount,
            path,
            keys: keyNames,
            message: "Dry run only; Vault was not modified.",
          };
        }
        if (runtime.allowWrite === false) throw new Error("Vault writes are disabled by plugin config.");
        if (params.confirmation !== WRITE_CONFIRMATION) {
          throw new Error(`Real writes require confirmation exactly ${WRITE_CONFIRMATION}.`);
        }
        const client = createVaultClient(runtime);
        const result = await client.writeSecret(path, data, { mount, cas: params.cas });
        return {
          dryRun: false,
          mount: result.mount,
          path: result.path,
          version: result.version,
          createdTime: result.createdTime,
          keys: keyNames,
        };
      }),
    });

    api.registerTool({
      name: "vault_external_secret_status",
      description: "Summarize ExternalSecret and ClusterSecretStore readiness. Does not read Kubernetes Secret values.",
      parameters: {
        type: "object",
        additionalProperties: false,
        properties: {
          namespace: { type: "string" },
          name: { type: "string" },
          storeName: { type: "string", description: "ClusterSecretStore name, normally vault-backend." },
        },
      },
      execute: async (_callId, params = {}) => executeSafe("vault_external_secret_status", async () => {
        return { result: await externalSecretStatus(resolveRuntime(api), params) };
      }),
    });

    api.registerTool({
      name: "vault_render_externalsecret",
      description: "Render an ExternalSecret manifest for a Vault KV v2 path. It only returns YAML and never applies it.",
      parameters: {
        type: "object",
        additionalProperties: false,
        required: ["namespace", "name", "vaultPath", "keys"],
        properties: {
          namespace: { type: "string" },
          name: { type: "string" },
          secretName: { type: "string" },
          vaultPath: pathParam,
          keys: {
            type: "array",
            items: { type: "string" },
          },
          storeName: { type: "string" },
          refreshInterval: { type: "string" },
        },
      },
      execute: async (_callId, params = {}) => executeSafe("vault_render_externalsecret", async () => {
        return { yaml: renderExternalSecret(params) };
      }),
    });

    api.registerTool({
      name: "vault_map_consumers",
      description: "Map Kubernetes workloads that reference a Secret by env/envFrom/volume. Does not read Secret values.",
      parameters: {
        type: "object",
        additionalProperties: false,
        properties: {
          namespace: { type: "string" },
          secretName: { type: "string" },
        },
      },
      execute: async (_callId, params = {}) => executeSafe("vault_map_consumers", async () => {
        return { result: await mapConsumers(resolveRuntime(api), params) };
      }),
    });

    api.registerTool({
      name: "vault_capabilities",
      description: "Ask Vault for the current token capabilities on one or more API paths. Does not expose token values.",
      parameters: {
        type: "object",
        additionalProperties: false,
        properties: {
          paths: {
            type: "array",
            items: { type: "string" },
            description: "Vault API paths such as secret/data/foo or secret/metadata/foo.",
          },
          mount: mountParam,
          path: pathParam,
        },
      },
      execute: async (_callId, params = {}) => executeSafe("vault_capabilities", async () => {
        const runtime = resolveRuntime(api);
        const client = createVaultClient(runtime);
        let paths = Array.isArray(params.paths) ? params.paths : [];
        if (paths.length === 0 && params.path !== undefined) {
          const mount = normalizeMount(params.mount || runtime.mount);
          paths = [kvPath(mount, "metadata", params.path), kvPath(mount, "data", params.path)];
        }
        return { result: await client.capabilities(paths) };
      }),
    });
  },
};

module.exports = plugin;
module.exports.default = plugin;
module.exports.VAULT_TOOL_NAMES = VAULT_TOOL_NAMES;
module.exports.REVEAL_CONFIRMATION = REVEAL_CONFIRMATION;
module.exports.WRITE_CONFIRMATION = WRITE_CONFIRMATION;
