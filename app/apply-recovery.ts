import type { JsonObject } from "./api-client";

export function recoveredApplyConfirmed(targetRevision: string, status: JsonObject, traffic: JsonObject): boolean {
  const lastApply = status.last_apply as JsonObject | undefined;
  const revision = status.active_revision ?? lastApply?.revision;
  return Boolean(targetRevision) && revision === targetRevision && status.apply_pending === false && traffic.traffic_ready === true;
}
