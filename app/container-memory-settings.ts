export function memoryMiB(value: unknown): string {
  if (typeof value !== "number" && typeof value !== "string") return "";
  const match = String(value).trim().match(/^(\d+(?:\.\d+)?)\s*(B|KiB|MiB|GiB)?$/);
  if (!match) return "";
  const factor: Record<string, number> = { B: 1, KiB: 1024, MiB: 1048576, GiB: 1073741824 };
  const mib = Number(match[1]) * (factor[match[2] ?? "B"] / 1048576);
  return Number.isSafeInteger(mib) && mib > 0 ? String(mib) : "";
}

export function validMemoryMiB(high: string, maximum: string): boolean {
  if (!/^\d+$/.test(high) || !/^\d+$/.test(maximum)) return false;
  const h = Number(high), m = Number(maximum);
  return Number.isSafeInteger(h) && Number.isSafeInteger(m) && h >= 16 && h <= m && m <= 8192;
}
