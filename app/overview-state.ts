import type { JsonObject } from "./api-client";

// Retain display-only LAN links during a failed inventory refresh. Never reuse
// a WAN address or turn stale inventory into authorization for an operation.
export function mergeOverviewState(previous: JsonObject | undefined, incoming: JsonObject): JsonObject {
  const nextAddress = incoming.connection_address as JsonObject | undefined;
  const oldAddress = previous?.connection_address as JsonObject | undefined;
  if (nextAddress?.inventory_ready === true || !Array.isArray(oldAddress?.local_addresses)) return incoming;
  return {
    ...incoming,
    connection_address: { ...nextAddress, local_addresses: oldAddress.local_addresses },
  };
}
