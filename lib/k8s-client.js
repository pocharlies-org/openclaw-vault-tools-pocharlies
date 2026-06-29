"use strict";

const { spawn } = require("node:child_process");
const { cleanObject, cleanString } = require("./vault-client");

function runKubectl(runtime, args) {
  const kubectlBin = cleanString(runtime.kubectlBin) || "kubectl";
  const timeoutMs = Number.parseInt(String(runtime.requestTimeoutMs || 15000), 10);
  return new Promise((resolve, reject) => {
    const child = spawn(kubectlBin, args, {
      stdio: ["ignore", "pipe", "pipe"],
      env: process.env,
    });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill("SIGTERM");
      reject(new Error(`kubectl timed out after ${timeoutMs}ms`));
    }, Number.isFinite(timeoutMs) ? timeoutMs : 15000);

    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString("utf8");
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString("utf8");
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (code === 0) return resolve(stdout);
      reject(new Error(`kubectl ${args.join(" ")} failed with exit ${code}: ${stderr.slice(0, 800)}`));
    });
  });
}

async function kubectlJson(runtime, args) {
  const text = await runKubectl(runtime, [...args, "-o", "json"]);
  return JSON.parse(text || "{}");
}

function conditionStatus(conditions, type) {
  const match = Array.isArray(conditions) ? conditions.find((condition) => condition.type === type) : null;
  if (!match) return { status: "Unknown" };
  return {
    status: match.status,
    reason: match.reason,
    message: match.message,
    lastTransitionTime: match.lastTransitionTime,
  };
}

function parseExternalSecret(item) {
  const metadata = cleanObject(item.metadata);
  const spec = cleanObject(item.spec);
  const status = cleanObject(item.status);
  return {
    namespace: metadata.namespace,
    name: metadata.name,
    secretStoreRef: spec.secretStoreRef || null,
    targetSecretName: spec.target && spec.target.name,
    refreshInterval: spec.refreshInterval,
    ready: conditionStatus(status.conditions, "Ready"),
    syncedResourceVersion: status.syncedResourceVersion,
  };
}

function parseClusterSecretStore(item) {
  const metadata = cleanObject(item.metadata);
  const spec = cleanObject(item.spec);
  const status = cleanObject(item.status);
  const provider = cleanObject(spec.provider && spec.provider.vault);
  return {
    name: metadata.name,
    ready: conditionStatus(status.conditions, "Ready"),
    capabilities: status.capabilities,
    vault: provider
      ? {
          server: provider.server,
          path: provider.path,
          version: provider.version,
          auth: provider.auth ? Object.keys(provider.auth).sort() : [],
        }
      : null,
  };
}

async function externalSecretStatus(runtime, params = {}) {
  const namespace = cleanString(params.namespace);
  const name = cleanString(params.name);
  const storeName = cleanString(params.storeName || params.clusterSecretStore);
  const storeJson = await kubectlJson(runtime, ["get", "clustersecretstore.external-secrets.io"]);
  const externalArgs = namespace
    ? ["get", "externalsecret.external-secrets.io", "-n", namespace]
    : ["get", "externalsecret.external-secrets.io", "-A"];
  const externalJson = await kubectlJson(runtime, externalArgs);

  let stores = (storeJson.items || []).map(parseClusterSecretStore);
  let externalSecrets = (externalJson.items || []).map(parseExternalSecret);
  if (storeName) stores = stores.filter((store) => store.name === storeName);
  if (name) externalSecrets = externalSecrets.filter((secret) => secret.name === name);
  if (storeName) {
    externalSecrets = externalSecrets.filter((secret) => {
      const ref = secret.secretStoreRef || {};
      return ref.name === storeName || (!ref.name && storeName === "vault-backend");
    });
  }
  return {
    stores,
    externalSecrets,
    summary: {
      stores: stores.length,
      externalSecrets: externalSecrets.length,
      ready: externalSecrets.filter((secret) => secret.ready.status === "True").length,
      notReady: externalSecrets.filter((secret) => secret.ready.status !== "True"),
    },
  };
}

function workloadName(item) {
  const metadata = cleanObject(item.metadata);
  return {
    namespace: metadata.namespace,
    name: metadata.name,
    kind: item.kind,
  };
}

function podTemplateSpec(item) {
  const spec = cleanObject(item.spec);
  if (spec.template) return cleanObject(spec.template.spec);
  if (item.kind === "CronJob") return cleanObject(spec.jobTemplate && spec.jobTemplate.spec && spec.jobTemplate.spec.template && spec.jobTemplate.spec.template.spec);
  return cleanObject(spec);
}

function secretRefsForWorkload(item) {
  const podSpec = podTemplateSpec(item);
  const refs = [];
  for (const container of [...(podSpec.initContainers || []), ...(podSpec.containers || [])]) {
    for (const envFrom of container.envFrom || []) {
      if (envFrom.secretRef && envFrom.secretRef.name) {
        refs.push({ source: "envFrom", container: container.name, secretName: envFrom.secretRef.name });
      }
    }
    for (const env of container.env || []) {
      const secretKeyRef = env.valueFrom && env.valueFrom.secretKeyRef;
      if (secretKeyRef && secretKeyRef.name) {
        refs.push({ source: "env", container: container.name, envName: env.name, secretName: secretKeyRef.name, key: secretKeyRef.key });
      }
    }
  }
  for (const volume of podSpec.volumes || []) {
    if (volume.secret && volume.secret.secretName) {
      refs.push({ source: "volume", volume: volume.name, secretName: volume.secret.secretName });
    }
  }
  return refs;
}

async function mapConsumers(runtime, params = {}) {
  const namespace = cleanString(params.namespace);
  const secretName = cleanString(params.secretName || params.secret);
  const args = namespace
    ? ["get", "deploy,statefulset,daemonset,job,cronjob", "-n", namespace]
    : ["get", "deploy,statefulset,daemonset,job,cronjob", "-A"];
  const json = await kubectlJson(runtime, args);
  const consumers = [];
  for (const item of json.items || []) {
    const refs = secretRefsForWorkload(item).filter((ref) => !secretName || ref.secretName === secretName);
    if (refs.length) consumers.push({ ...workloadName(item), refs });
  }
  return {
    namespace: namespace || "*",
    secretName: secretName || "*",
    consumers,
  };
}

function yamlQuote(value) {
  return JSON.stringify(String(value));
}

function renderExternalSecret(params = {}) {
  const namespace = cleanString(params.namespace);
  const name = cleanString(params.name);
  const secretName = cleanString(params.secretName || params.targetSecretName || name);
  const vaultPath = cleanString(params.vaultPath || params.path);
  const storeName = cleanString(params.storeName || params.clusterSecretStore || "vault-backend");
  const refreshInterval = cleanString(params.refreshInterval || "1h");
  const keys = Array.isArray(params.keys) ? params.keys.map(cleanString).filter(Boolean) : [];
  if (!namespace) throw new Error("namespace is required");
  if (!name) throw new Error("name is required");
  if (!secretName) throw new Error("secretName is required");
  if (!vaultPath) throw new Error("vaultPath is required");
  if (keys.length === 0) throw new Error("keys must contain at least one key");

  const remoteRefs = keys
    .map(
      (key) => [
        `  - secretKey: ${yamlQuote(key)}`,
        "    remoteRef:",
        `      key: ${yamlQuote(vaultPath)}`,
        `      property: ${yamlQuote(key)}`,
      ].join("\n"),
    )
    .join("\n");

  return [
    "apiVersion: external-secrets.io/v1",
    "kind: ExternalSecret",
    "metadata:",
    `  name: ${yamlQuote(name)}`,
    `  namespace: ${yamlQuote(namespace)}`,
    "spec:",
    `  refreshInterval: ${yamlQuote(refreshInterval)}`,
    "  secretStoreRef:",
    `    name: ${yamlQuote(storeName)}`,
    "    kind: ClusterSecretStore",
    "  target:",
    `    name: ${yamlQuote(secretName)}`,
    "    creationPolicy: Owner",
    "  data:",
    remoteRefs,
    "",
  ].join("\n");
}

module.exports = {
  externalSecretStatus,
  mapConsumers,
  parseClusterSecretStore,
  parseExternalSecret,
  renderExternalSecret,
  runKubectl,
  secretRefsForWorkload,
};
