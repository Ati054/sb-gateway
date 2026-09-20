import type { JsonObject } from "./api-client";

function asRecord(value: unknown): JsonObject {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as JsonObject)
    : {};
}

export function reverseAvailability(runtime: JsonObject | undefined, exitId: string, now: number) {
  const candidate = `reverse-vless-${exitId}`;
  let latest = 0;
  let available: boolean | undefined;
  for (const raw of Object.values(asRecord(runtime?.selector_health))) {
    const health = asRecord(raw);
    const checked = Date.parse(String(health.checked_at ?? ""));
    const probed = Number(asRecord(health.last_probe_at)[candidate]) * 1000;
    const limits = asRecord(health.probe_limits);
    const shortlist = Array.isArray(health.shortlist) ? health.shortlist : [];
    const interval = health.selected === candidate ? Number(limits.active_seconds ?? 60)
      : shortlist.includes(candidate) ? Number(limits.backup_seconds ?? 300)
        : Number(limits.full_scan_seconds ?? 1800);
    const value = asRecord(health.availability_ok)[candidate];
    if (health.runtime_error || !Number.isFinite(checked) || !Number.isFinite(probed)
      || probed <= 0 || now - checked > Math.max(120, Number(limits.active_seconds ?? 60) + 60) * 1000
      || now - probed > (interval + 120) * 1000 || probed > now + 60_000
      || typeof value !== "boolean" || probed <= latest) continue;
    latest = probed;
    available = value;
  }
  return available === true ? { state: "available", label: "Доступен" }
    : available === false ? { state: "unavailable", label: "Недоступен" }
      : { state: "unknown", label: "Нет актуальной проверки" };
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
        for (const field of ["runtime_selected", "runtime_confirmed", "runtime_observed_at", "runtime_error", "candidate_labels", "candidate_count", "availability_ok", "shortlist"]) {
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
