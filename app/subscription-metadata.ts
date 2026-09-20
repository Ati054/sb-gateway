import type { JsonObject } from "./api-client";

export function mergeSubscriptionMetadata(
  previous: Record<string, JsonObject>,
  incoming: Record<string, JsonObject>,
  ids: string[],
): Record<string, JsonObject> {
  return Object.fromEntries(ids.flatMap((id) => {
    const old = previous[id];
    const next = incoming[id];
    if (!next) return old ? [[id, old]] : [];
    const oldTime = Date.parse(String(old?.refreshed_at ?? ""));
    const nextTime = Date.parse(String(next.refreshed_at ?? ""));
    const keepOld = Number.isFinite(oldTime) && (!Number.isFinite(nextTime) || nextTime < oldTime);
    return [[id, keepOld ? old : next]];
  }));
}
