export function acmeDNSTimeoutMinutes(value: string): number | undefined {
  const minutes = Number(value);
  return /^\d+$/.test(value) && Number.isSafeInteger(minutes) && minutes >= 1 && minutes <= 1440 ? minutes : undefined;
}
