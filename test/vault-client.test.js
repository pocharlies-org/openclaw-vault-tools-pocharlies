"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const manifest = require("../openclaw.plugin.json");
const plugin = require("../index");
const {
  VaultClient,
  kvPath,
  normalizeLogicalPath,
  redactData,
} = require("../lib/vault-client");
const {
  parseClusterSecretStore,
  parseExternalSecret,
  renderExternalSecret,
} = require("../lib/k8s-client");

test("normalizes KV v2 logical paths", () => {
  assert.equal(normalizeLogicalPath("/foo/bar/"), "foo/bar");
  assert.equal(kvPath("secret/", "metadata", "/foo/bar/"), "secret/metadata/foo/bar");
  assert.equal(kvPath("/secret", "data", "foo"), "secret/data/foo");
  assert.throws(() => normalizeLogicalPath("foo/../bar"), /must not contain/);
});

test("redacts values by default without leaking previews", () => {
  assert.deepEqual(redactData({ password: "secret-value", count: 3, nested: { token: "x" } }), {
    count: { redacted: true, type: "number" },
    nested: { redacted: true, type: "object", keys: ["token"] },
    password: { redacted: true, type: "string", length: 12 },
  });
});

test("secret read reveal requires exact confirmation", async () => {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    return {
      ok: true,
      status: 200,
      text: async () => JSON.stringify({
        data: {
          data: { password: "secret-value" },
          metadata: { version: 1 },
        },
      }),
    };
  };
  const fs = { readFile: async () => "limited-token" };
  const client = new VaultClient({ vaultAddr: "http://vault", authMode: "token", tokenFile: "/token" }, { fetchImpl, fs });
  const result = await client.readSecret("app/config");
  assert.equal(result.data.password, "secret-value");
  assert.equal(calls[0].init.headers["X-Vault-Token"], "limited-token");

  const api = {
    pluginConfig: { vaultAddr: "http://vault", authMode: "token", tokenFile: "/token" },
    registerTool(tool) {
      if (tool.name === "vault_secret_read") this.tool = tool;
    },
  };
  plugin.register(api);
  global.fetch = fetchImpl;
  const originalReadFile = require("node:fs/promises").readFile;
  require("node:fs/promises").readFile = async () => "limited-token";
  try {
    const redacted = JSON.parse((await api.tool.execute("1", { path: "app/config", reveal: true })).content[0].text);
    assert.equal(redacted.ok, true);
    assert.equal(redacted.revealed, false);
    assert.equal(redacted.data.password.redacted, true);

    const revealed = JSON.parse((await api.tool.execute("2", {
      path: "app/config",
      reveal: true,
      confirmation: "REVEAL_SECRET_VALUES",
    })).content[0].text);
    assert.equal(revealed.ok, true);
    assert.equal(revealed.revealed, true);
    assert.equal(revealed.data.password, "secret-value");
  } finally {
    require("node:fs/promises").readFile = originalReadFile;
  }
});

test("write defaults to dry-run and requires confirmation for real writes", async () => {
  const registered = {};
  const api = {
    pluginConfig: { vaultAddr: "http://vault", authMode: "token", tokenFile: "/token" },
    registerTool(tool) {
      registered[tool.name] = tool;
    },
  };
  plugin.register(api);

  const dryRun = JSON.parse((await registered.vault_secret_write.execute("1", {
    path: "openclaw-vault-tools/smoke",
    data: { value: "synthetic" },
  })).content[0].text);
  assert.equal(dryRun.ok, true);
  assert.equal(dryRun.dryRun, true);
  assert.deepEqual(dryRun.keys, ["value"]);
  assert.equal(JSON.stringify(dryRun).includes("synthetic"), false);

  const blocked = JSON.parse((await registered.vault_secret_write.execute("2", {
    path: "openclaw-vault-tools/smoke",
    data: { value: "synthetic" },
    dry_run: false,
  })).content[0].text);
  assert.equal(blocked.ok, false);
  assert.match(blocked.error, /WRITE_VAULT_SECRET/);
});

test("manifest exports no delete or destroy tools", () => {
  const tools = manifest.contracts.tools;
  assert.deepEqual(tools, plugin.VAULT_TOOL_NAMES);
  assert.equal(tools.some((name) => /delete|destroy/i.test(name)), false);
});

test("ExternalSecret status parsing avoids secret values", () => {
  const store = parseClusterSecretStore({
    metadata: { name: "vault-backend" },
    spec: {
      provider: {
        vault: {
          server: "http://vault.vault.svc.cluster.local:8200",
          path: "secret",
          version: "v2",
          auth: { kubernetes: { role: "external-secrets" } },
        },
      },
    },
    status: {
      capabilities: "ReadWrite",
      conditions: [{ type: "Ready", status: "True", reason: "Valid" }],
    },
  });
  assert.equal(store.name, "vault-backend");
  assert.deepEqual(store.vault.auth, ["kubernetes"]);

  const external = parseExternalSecret({
    metadata: { namespace: "openclaw-qwen36", name: "openclaw-secret" },
    spec: { target: { name: "openclaw-secret" }, secretStoreRef: { name: "vault-backend" } },
    status: { conditions: [{ type: "Ready", status: "True" }] },
  });
  assert.equal(external.ready.status, "True");
});

test("renders ExternalSecret manifest only", () => {
  const yaml = renderExternalSecret({
    namespace: "openclaw-qwen36",
    name: "vault-tools-smoke",
    secretName: "vault-tools-smoke",
    vaultPath: "openclaw-vault-tools/smoke",
    keys: ["username", "password"],
  });
  assert.match(yaml, /kind: ExternalSecret/);
  assert.match(yaml, /remoteRef:/);
  assert.equal(yaml.includes("password-value"), false);
});
