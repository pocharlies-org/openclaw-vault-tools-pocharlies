"use strict";

const fs = require("node:fs/promises");

const DEFAULTS = {
  vaultAddr: "http://127.0.0.1:8200",
  mount: "secret",
  engineVersion: "v2",
  authMode: "kubernetes",
  kubernetesMountPath: "kubernetes",
  kubernetesRole: "openclaw-vault-tools",
  kubernetesJwtPath: "/var/run/secrets/kubernetes.io/serviceaccount/token",
  tokenEnv: "VAULT_TOKEN",
  requestTimeoutMs: 15000,
  allowReveal: true,
  allowWrite: true,
  readValueMaxChars: 131072,
};

function cleanString(value) {
  return typeof value === "string" ? value.trim() : "";
}

function cleanObject(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function asBool(value, fallback) {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    if (["1", "true", "yes", "on"].includes(normalized)) return true;
    if (["0", "false", "no", "off"].includes(normalized)) return false;
  }
  return fallback;
}

function clampInt(value, fallback, min, max) {
  const parsed = Number.parseInt(String(value ?? ""), 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(min, Math.min(max, parsed));
}

function normalizeVaultAddr(value) {
  const raw = cleanString(value) || DEFAULTS.vaultAddr;
  return raw.replace(/\/+$/, "");
}

function normalizeMount(value) {
  const cleaned = cleanString(value || DEFAULTS.mount).replace(/^\/+|\/+$/g, "");
  if (!cleaned || cleaned.includes("..")) throw new Error("mount must be a non-empty Vault mount name");
  return cleaned;
}

function normalizeLogicalPath(value) {
  const cleaned = cleanString(value).replace(/^\/+|\/+$/g, "");
  if (!cleaned) return "";
  const parts = cleaned.split("/").filter(Boolean);
  if (parts.some((part) => part === "." || part === "..")) {
    throw new Error("path must not contain '.' or '..' segments");
  }
  return parts.join("/");
}

function kvPath(mount, kind, logicalPath) {
  const normalizedMount = normalizeMount(mount);
  const normalizedPath = normalizeLogicalPath(logicalPath);
  if (!["data", "metadata"].includes(kind)) throw new Error(`unsupported KV v2 path kind: ${kind}`);
  return normalizedPath ? `${normalizedMount}/${kind}/${normalizedPath}` : `${normalizedMount}/${kind}`;
}

function redactedScalar(value) {
  if (value === null) return { redacted: true, type: "null" };
  if (Array.isArray(value)) return { redacted: true, type: "array", length: value.length };
  const valueType = typeof value;
  if (valueType === "string") return { redacted: true, type: "string", length: value.length };
  if (valueType === "number" || valueType === "boolean") return { redacted: true, type: valueType };
  if (valueType === "object") return { redacted: true, type: "object", keys: Object.keys(value).sort() };
  return { redacted: true, type: valueType };
}

function redactData(value) {
  if (Array.isArray(value)) return value.map((item) => redactedScalar(item));
  if (!value || typeof value !== "object") return redactedScalar(value);
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, redactedScalar(value[key])]));
}

function pickKeys(data, keys) {
  if (!Array.isArray(keys) || keys.length === 0) return data;
  const wanted = new Set(keys.map(cleanString).filter(Boolean));
  return Object.fromEntries(Object.entries(cleanObject(data)).filter(([key]) => wanted.has(key)));
}

function sanitizeError(error) {
  const message = error instanceof Error ? error.message : String(error || "unknown error");
  return message
    .replace(/X-Vault-Token:\s*[^\s]+/gi, "X-Vault-Token: [redacted]")
    .replace(/client_token["']?\s*:\s*["'][^"']+["']/gi, 'client_token:"[redacted]"')
    .replace(/token["']?\s*:\s*["'][^"']+["']/gi, 'token:"[redacted]"');
}

function resolveVaultConfig(config = {}, env = process.env) {
  const source = cleanObject(config);
  return {
    vaultAddr: normalizeVaultAddr(cleanString(source.vaultAddr) || cleanString(env.VAULT_ADDR) || DEFAULTS.vaultAddr),
    mount: normalizeMount(source.mount || DEFAULTS.mount),
    engineVersion: "v2",
    authMode: cleanString(source.authMode || env.VAULT_AUTH_MODE || DEFAULTS.authMode),
    kubernetesMountPath: normalizeLogicalPath(source.kubernetesMountPath || DEFAULTS.kubernetesMountPath),
    kubernetesRole: cleanString(source.kubernetesRole || DEFAULTS.kubernetesRole),
    kubernetesJwtPath: cleanString(source.kubernetesJwtPath || DEFAULTS.kubernetesJwtPath),
    tokenFile: cleanString(source.tokenFile || env.VAULT_TOKEN_FILE),
    tokenEnv: cleanString(source.tokenEnv || DEFAULTS.tokenEnv),
    requestTimeoutMs: clampInt(source.requestTimeoutMs, DEFAULTS.requestTimeoutMs, 1000, 120000),
    allowReveal: asBool(source.allowReveal, DEFAULTS.allowReveal),
    allowWrite: asBool(source.allowWrite, DEFAULTS.allowWrite),
    readValueMaxChars: clampInt(source.readValueMaxChars, DEFAULTS.readValueMaxChars, 1, 1048576),
  };
}

class VaultClient {
  constructor(config = {}, options = {}) {
    this.config = resolveVaultConfig(config, options.env || process.env);
    this.fetchImpl = options.fetchImpl || globalThis.fetch;
    this.fs = options.fs || fs;
    this.cachedToken = "";
    this.cachedTokenExpiresAt = 0;
    if (typeof this.fetchImpl !== "function") {
      throw new Error("global fetch is required (Node.js >=18)");
    }
  }

  async status() {
    const route = "/v1/sys/health?standbyok=true&perfstandbyok=true";
    const { status, body } = await this.rawRequest(route, { method: "GET", auth: false, allowErrorStatus: true });
    return {
      reachable: status >= 200 && status < 600,
      httpStatus: status,
      initialized: body.initialized,
      sealed: body.sealed,
      standby: body.standby,
      performanceStandby: body.performance_standby,
      version: body.version,
      clusterName: body.cluster_name,
      clusterId: body.cluster_id,
    };
  }

  async listPaths(path = "", options = {}) {
    const mount = normalizeMount(options.mount || this.config.mount);
    const route = `/v1/${kvPath(mount, "metadata", path)}?list=true`;
    const body = await this.request(route, { method: "LIST" });
    return {
      mount,
      path: normalizeLogicalPath(path),
      keys: Array.isArray(body.data && body.data.keys) ? body.data.keys : [],
    };
  }

  async metadata(path, options = {}) {
    const mount = normalizeMount(options.mount || this.config.mount);
    const route = `/v1/${kvPath(mount, "metadata", path)}`;
    const body = await this.request(route, { method: "GET" });
    const data = cleanObject(body.data);
    return {
      mount,
      path: normalizeLogicalPath(path),
      createdTime: data.created_time,
      currentVersion: data.current_version,
      maxVersions: data.max_versions,
      oldestVersion: data.oldest_version,
      updatedTime: data.updated_time,
      versions: data.versions || {},
      customMetadata: data.custom_metadata || {},
    };
  }

  async readSecret(path, options = {}) {
    const mount = normalizeMount(options.mount || this.config.mount);
    const query = options.version ? `?version=${encodeURIComponent(String(options.version))}` : "";
    const route = `/v1/${kvPath(mount, "data", path)}${query}`;
    const body = await this.request(route, { method: "GET" });
    const data = cleanObject(body.data && body.data.data);
    const metadata = cleanObject(body.data && body.data.metadata);
    return {
      mount,
      path: normalizeLogicalPath(path),
      data,
      metadata,
    };
  }

  async writeSecret(path, data, options = {}) {
    const mount = normalizeMount(options.mount || this.config.mount);
    const payload = { data: cleanObject(data) };
    if (options.cas !== undefined && options.cas !== null && options.cas !== "") {
      payload.options = { cas: Number.parseInt(String(options.cas), 10) };
      if (!Number.isFinite(payload.options.cas)) throw new Error("cas must be an integer when provided");
    }
    const body = await this.request(`/v1/${kvPath(mount, "data", path)}`, {
      method: "POST",
      body: payload,
    });
    return {
      mount,
      path: normalizeLogicalPath(path),
      version: body.data && body.data.version,
      createdTime: body.data && body.data.created_time,
    };
  }

  async capabilities(paths) {
    const normalized = (Array.isArray(paths) ? paths : [paths]).map(cleanString).filter(Boolean);
    if (normalized.length === 0) throw new Error("paths must contain at least one Vault API path");
    const body = await this.request("/v1/sys/capabilities-self", {
      method: "POST",
      body: { paths: normalized },
    });
    return body.capabilities ? { capabilities: body.capabilities } : body.data || body;
  }

  async request(route, options = {}) {
    const { body } = await this.rawRequest(route, options);
    return body;
  }

  async rawRequest(route, options = {}) {
    const auth = options.auth !== false;
    const headers = {
      accept: "application/json",
      ...(options.headers || {}),
    };
    let requestBody;
    if (options.body !== undefined) {
      headers["content-type"] = "application/json";
      requestBody = JSON.stringify(options.body);
    }
    if (auth) headers["X-Vault-Token"] = await this.ensureToken();

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.requestTimeoutMs);
    let response;
    let text;
    try {
      response = await this.fetchImpl(`${this.config.vaultAddr}${route}`, {
        method: options.method || "GET",
        headers,
        body: requestBody,
        signal: controller.signal,
      });
      text = await response.text();
    } catch (error) {
      throw new Error(`Vault request failed: ${sanitizeError(error)}`);
    } finally {
      clearTimeout(timeout);
    }

    let parsed = {};
    if (text) {
      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = { text: text.slice(0, 1000) };
      }
    }
    if (!response.ok && !options.allowErrorStatus) {
      const detail = Array.isArray(parsed.errors)
        ? parsed.errors.join("; ")
        : parsed.error || parsed.text || response.statusText;
      throw new Error(`Vault ${route} HTTP ${response.status}: ${sanitizeError(detail)}`);
    }
    return { status: response.status, body: parsed };
  }

  async ensureToken() {
    const now = Date.now();
    if (this.cachedToken && this.cachedTokenExpiresAt > now + 5000) return this.cachedToken;
    if (this.config.authMode === "none") {
      throw new Error("Vault authMode=none cannot call authenticated Vault endpoints");
    }

    const tokenFromEnvName = this.config.tokenEnv;
    const tokenFromEnv = tokenFromEnvName ? cleanString(process.env[tokenFromEnvName]) : "";
    if (tokenFromEnv) {
      this.cachedToken = tokenFromEnv;
      this.cachedTokenExpiresAt = now + 10 * 60 * 1000;
      return this.cachedToken;
    }

    if (this.config.tokenFile) {
      const token = cleanString(await this.fs.readFile(this.config.tokenFile, "utf8"));
      if (!token) throw new Error("Vault token file is empty");
      this.cachedToken = token;
      this.cachedTokenExpiresAt = now + 10 * 60 * 1000;
      return this.cachedToken;
    }

    if (this.config.authMode === "kubernetes") {
      const jwt = cleanString(await this.fs.readFile(this.config.kubernetesJwtPath, "utf8"));
      if (!jwt) throw new Error("Kubernetes service account token file is empty");
      const mount = normalizeLogicalPath(this.config.kubernetesMountPath || "kubernetes");
      const body = await this.request(`/v1/auth/${mount}/login`, {
        method: "POST",
        auth: false,
        body: {
          role: this.config.kubernetesRole,
          jwt,
        },
      });
      const auth = cleanObject(body.auth);
      const token = cleanString(auth.client_token);
      if (!token) throw new Error("Vault Kubernetes login did not return a client token");
      const ttlMs = clampInt(auth.lease_duration, 300, 60, 3600) * 1000;
      this.cachedToken = token;
      this.cachedTokenExpiresAt = now + Math.floor(ttlMs * 0.8);
      return this.cachedToken;
    }

    throw new Error("Vault auth is not configured. Set tokenFile/tokenEnv or Kubernetes auth settings.");
  }
}

module.exports = {
  DEFAULTS,
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
};
