import type { JsonObject } from "./api-client";

function objectValue(value: unknown): JsonObject {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as JsonObject)
    : {};
}

export function disableSubscriptionPublication(config: JsonObject): JsonObject {
  return {
    ...config,
    ingress: {
      ...objectValue(config.ingress),
      subscription_endpoint_enabled: false,
    },
  };
}
