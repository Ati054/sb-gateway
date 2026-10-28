import type { JsonObject } from "./api-client";

function asRecord(value: unknown): JsonObject {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as JsonObject)
    : {};
}

export function reverseAvailability(runtime: JsonObject | undefined, exitId: string, now: number) {
  const telemetry = asRecord(runtime?.reverse_telemetry);
  const sampled = Date.parse(String(telemetry.sampled_at ?? ""));
  const connected = asRecord(telemetry.reverse_connections)[exitId];
  const sources = asRecord(telemetry.sources);
  const onlineSource = sources.xray_online ?? sources.xray;
  if (onlineSource !== "available"
    || !Number.isFinite(sampled) || !Number.isFinite(now)
    || now - sampled > 75_000 || sampled > now + 5_000
    || typeof connected !== "boolean") {
    return { state: "unknown", label: "Нет актуального статуса подключения" };
  }
  return connected ? { state: "available", label: "Подключён" }
    : { state: "unavailable", label: "Не подключён" };
}

export function mergeRuntimeStatus(
  previousValue: JsonObject | undefined,
  incomingValue: JsonObject,
): JsonObject {
  const previous = asRecord(previousValue);
  const incoming = asRecord(incomingValue);
  const previousSelectorHealth = asRecord(previous.selector_health);
  const incomingSelectorHealth = asRecord(incoming.selector_health);
  const selectorKeys = new Set([
    ...Object.keys(previousSelectorHealth),
    ...Object.keys(incomingSelectorHealth),
  ]);
  const selectorHealth = Object.fromEntries(
    [...selectorKeys].map((key) => {
      const old = asRecord(previousSelectorHealth[key]);
      const next = asRecord(incomingSelectorHealth[key]);
      const merged = { ...old, ...next };
      const oldTime = Date.parse(String(old.runtime_observed_at ?? ""));
      const nextTime = Date.parse(String(next.runtime_observed_at ?? ""));
      // A slow history response must not roll back a newer runtime readback.
      if (Number.isFinite(oldTime) && (!Number.isFinite(nextTime) || nextTime < oldTime)) {
        for (const field of ["runtime_selected", "runtime_confirmed", "runtime_observed_at", "runtime_error", "candidate_labels", "candidate_count", "availability_ok", "shortlist", "latency_comparisons", "last_latency_comparisons"]) {
          if (field in old) merged[field] = old[field];
        }
      }
      return [key, merged];
    }),
  );
  return {
    ...previous,
    ...incoming,
    selector_health: selectorHealth,
  };
}
