const tenantItem = /^\/v1\/tenants\/[^/]+$/u;
const tenantFreeze = /^\/v1\/tenants\/[^/]+\/freeze$/u;
const tenantQuota = /^\/v1\/tenants\/[^/]+\/quota$/u;
const deploymentItem = /^\/v1\/tenants\/[^/]+\/deployments\/[^/]+$/u;
const deploymentRollout = /^\/v1\/tenants\/[^/]+\/deployments\/[^/]+\/rollout$/u;
const projectItem = /^\/v1\/tenants\/[^/]+\/projects\/[^/]+$/u;
const scheduleItem = /^\/v1\/tenants\/[^/]+\/schedules\/[^/]+$/u;
const interactionResponse = /^\/v1\/tenants\/[^/]+\/interactions\/[^/]+\/response$/u;
const commandSubmission = /^\/v1\/tenants\/[^/]+\/nodes\/[^/]+\/commands$/u;
const nodeItem = /^\/v1\/nodes\/[^/]+$/u;
const nodePlacement = /^\/v1\/nodes\/[^/]+\/placement$/u;
const nodeDrain = /^\/v1\/nodes\/[^/]+\/drain$/u;
const nodeCredential = /^\/v1\/node-credentials\/[^/]+$/u;
const operatorItem = /^\/v1\/operators\/[^/]+$/u;
const nodePoolItem = /^\/v1\/node-pools\/[^/]+$/u;
const nodeEvidenceCaptures = /^\/v1\/nodes\/[^/]+\/evidence\/captures$/u;
const nodeEvidenceCapture = /^\/v1\/nodes\/[^/]+\/evidence\/captures\/[^/]+$/u;
const nodeEvidenceCaptureSeal = /^\/v1\/nodes\/[^/]+\/evidence\/captures\/[^/]+\/seal$/u;
const snapshotQuarantine = /^\/v1\/tenants\/[^/]+\/nodes\/[^/]+\/snapshots\/[^/]+\/quarantine$/u;

export function consoleMutationAllowed(method, pathname) {
  const rules = {
    POST: [
      /^\/v1\/tenants$/u,
      /^\/v1\/operators$/u,
      /^\/v1\/enrollments$/u,
      /^\/v1\/tenants\/[^/]+\/task-requests$/u,
      /^\/v1\/tenants\/[^/]+\/schedules$/u,
      interactionResponse,
      commandSubmission,
      nodePlacement,
      nodeEvidenceCaptures,
      nodeEvidenceCaptureSeal,
    ],
    PUT: [
      tenantFreeze,
      tenantQuota,
      /^\/v1\/operations\/freeze$/u,
      deploymentItem,
      deploymentRollout,
      projectItem,
      nodeDrain,
      nodePoolItem,
      snapshotQuarantine,
    ],
    DELETE: [
      deploymentItem,
      projectItem,
      scheduleItem,
      nodeItem,
      nodeDrain,
      nodeCredential,
      operatorItem,
      nodePoolItem,
      nodeEvidenceCapture,
    ],
  };
  return (rules[method] || []).some((pattern) => pattern.test(pathname));
}

export function consoleReadAllowed(pathname) {
  return pathname.startsWith("/v1/");
}

export function canonicalID(value, label = "Identifier", maxLength = 128) {
  const result = String(value || "");
  if (!Number.isSafeInteger(maxLength) || maxLength < 1 || result.length > maxLength ||
      !/^[A-Za-z0-9][A-Za-z0-9._-]*$/u.test(result)) {
    throw new Error(label + " must start with a letter or number, use only letters, numbers, dot, underscore, or dash, and be at most " + maxLength + " characters.");
  }
  return result;
}

export function splitIDs(value, label = "Identifiers") {
  const values = String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  if (!values.length) {
    throw new Error(label + " must include at least one value.");
  }
  const unique = [...new Set(values.map((item) => canonicalID(item, label)))];
  unique.sort();
  return unique;
}

export function requestID(prefix) {
  const random = globalThis.crypto?.randomUUID?.().replaceAll("-", "");
  if (!random) {
    throw new Error("This browser cannot create a cryptographically random request identifier.");
  }
  return canonicalID(prefix + "-" + random.slice(0, 24), "Request ID");
}

export async function fileBase64(file, maxBytes, label) {
  if (!file) {
    throw new Error("Choose " + label + ".");
  }
  if (file.size <= 0 || file.size > maxBytes) {
    throw new Error(label + " must be between 1 byte and " + maxBytes.toLocaleString() + " bytes.");
  }
  const bytes = new Uint8Array(await file.arrayBuffer());
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary);
}

export function deploymentReplicaCount(deployment) {
  return Array.isArray(deployment?.instances) ? deployment.instances.length : 0;
}
