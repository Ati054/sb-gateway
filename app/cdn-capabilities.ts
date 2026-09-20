// Keep aligned with internal/cdnfeed. A CDN label is not evidence of a public
// origin feed: do not substitute ASN ranges, DNS answers, or delivery nodes.
export const AUTOMATIC_CIDR_PROVIDERS = [
  "cloudflare", "gcore", "edgecenter", "yandex", "beeline", "timeweb",
] as const;

export function supportsAutomaticCidr(provider: string): boolean {
  return AUTOMATIC_CIDR_PROVIDERS.some((id) => id === provider.trim().toLowerCase());
}

export function automaticCidrHint(provider: string): string {
  return provider === "cloudflare"
    ? "Автообновление. При ошибке сохраняется предыдущий список."
    : "Обновление каждые 15 минут. При ошибке сохраняется предыдущий список.";
}
