// SPDX-License-Identifier: Apache-2.0

export type KyntralRiskClass = "K0" | "K1" | "K2" | "K3" | "K4";
export type ExecutionLocation = "device" | "cloud" | "hybrid";
export type NetworkAccess = "none" | "allowlist";
export type DeviceDataCategory =
  | "none" | "notes" | "files" | "photos" | "clipboard" | "contacts"
  | "calendar" | "location" | "health" | "microphone" | "camera";
export type SideEffect =
  | "none" | "local-read" | "local-write" | "network-read" | "network-write"
  | "external-write" | "delete" | "financial" | "communication";

export type CapabilityManifestV1 = Readonly<{
  version: "kyntral.capability.v1";
  id: string;
  moduleVersion: string;
  publisher: Readonly<{ id: string; name: string; repository?: string }>;
  risk: KyntralRiskClass;
  execution: Readonly<{ location: ExecutionLocation; backgroundAllowed: boolean }>;
  deviceData: readonly DeviceDataCategory[];
  network: Readonly<{ access: NetworkAccess; domains?: readonly string[] }>;
  sideEffects: readonly SideEffect[];
  destinations?: readonly string[];
  minimumKyntralVersion?: string;
}>;

const ID = /^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)+$/;
const OPAQUE = /^[a-z][a-z0-9_-]{2,127}$/;
const SEMVER = /^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/;
const DOMAIN = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const RISKS = new Set<KyntralRiskClass>(["K0","K1","K2","K3","K4"]);
const LOCATIONS = new Set<ExecutionLocation>(["device","cloud","hybrid"]);
const DATA = new Set<DeviceDataCategory>(["none","notes","files","photos","clipboard","contacts","calendar","location","health","microphone","camera"]);
const EFFECTS = new Set<SideEffect>(["none","local-read","local-write","network-read","network-write","external-write","delete","financial","communication"]);

function asObject(value: unknown, field: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(field + " must be an object");
  return value as Record<string, unknown>;
}
function asString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(field + " must be a non-empty string");
  return value;
}
function uniqueStrings(value: unknown, field: string): string[] {
  if (!Array.isArray(value) || value.some((v) => typeof v !== "string")) throw new Error(field + " must be an array of strings");
  const result = value as string[];
  if (new Set(result).size !== result.length) throw new Error(field + " must not contain duplicates");
  return result;
}

export function assertCapabilityManifestV1(value: unknown): asserts value is CapabilityManifestV1 {
  const root = asObject(value, "manifest");
  if (root.version !== "kyntral.capability.v1") throw new Error("manifest.version must be kyntral.capability.v1");
  const id = asString(root.id, "manifest.id");
  if (!ID.test(id) || id.length > 160) throw new Error("manifest.id is invalid");
  const moduleVersion = asString(root.moduleVersion, "manifest.moduleVersion");
  if (!SEMVER.test(moduleVersion)) throw new Error("manifest.moduleVersion must be semver");

  const publisher = asObject(root.publisher, "manifest.publisher");
  if (!OPAQUE.test(asString(publisher.id, "manifest.publisher.id"))) throw new Error("manifest.publisher.id is invalid");
  if (asString(publisher.name, "manifest.publisher.name").length > 120) throw new Error("manifest.publisher.name is too long");
  if (publisher.repository !== undefined) {
    const repository = new URL(asString(publisher.repository, "manifest.publisher.repository"));
    if (repository.protocol !== "https:") throw new Error("manifest.publisher.repository must use HTTPS");
  }

  if (!RISKS.has(root.risk as KyntralRiskClass)) throw new Error("manifest.risk is invalid");
  const execution = asObject(root.execution, "manifest.execution");
  if (!LOCATIONS.has(execution.location as ExecutionLocation)) throw new Error("manifest.execution.location is invalid");
  if (typeof execution.backgroundAllowed !== "boolean") throw new Error("manifest.execution.backgroundAllowed must be boolean");

  const deviceData = uniqueStrings(root.deviceData, "manifest.deviceData");
  if (!deviceData.every((v) => DATA.has(v as DeviceDataCategory))) throw new Error("manifest.deviceData contains an unknown category");

  const network = asObject(root.network, "manifest.network");
  if (network.access !== "none" && network.access !== "allowlist") throw new Error("manifest.network.access is invalid");
  const domains = network.domains === undefined ? [] : uniqueStrings(network.domains, "manifest.network.domains");
  if (network.access === "none" && domains.length !== 0) throw new Error("network domains are forbidden when access is none");
  if (network.access === "allowlist" && (domains.length < 1 || domains.length > 50 || domains.some((domain) => !DOMAIN.test(domain)))) {
    throw new Error("network allowlist domains are invalid");
  }

  const sideEffects = uniqueStrings(root.sideEffects, "manifest.sideEffects");
  if (!sideEffects.every((v) => EFFECTS.has(v as SideEffect))) throw new Error("manifest.sideEffects contains an unknown effect");

  if (root.destinations !== undefined) {
    const destinations = uniqueStrings(root.destinations, "manifest.destinations");
    if (destinations.length > 25 || destinations.some((destination) => !OPAQUE.test(destination))) throw new Error("manifest.destinations is invalid");
  }
  if (root.minimumKyntralVersion !== undefined && !SEMVER.test(asString(root.minimumKyntralVersion, "manifest.minimumKyntralVersion"))) {
    throw new Error("manifest.minimumKyntralVersion must be semver");
  }
}

export function parseCapabilityManifestV1(value: unknown): CapabilityManifestV1 {
  assertCapabilityManifestV1(value);
  return value;
}
