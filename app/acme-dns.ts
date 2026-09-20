export type AcmeDNSAccount = { username: string; password: string; subdomain: string; fulldomain: string };
export type AcmeDNSDelegation = { domain: string; name: string; target: string };

const dnsName = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
export const acmeDNSDomains = (domains: string[]) => [...new Set(domains.map(name => name.replace(/^\*\./, "")))];

// Accept a single /register response, or a map of base domains to responses.
// Never expose JSON parser diagnostics: they may contain a fragment of a key.
export function importAcmeDNSAccounts(text: string, domains: string[]) {
  const names = acmeDNSDomains(domains);
  if (!names.length) throw new Error("Сначала укажите домены сертификата.");
  if (new TextEncoder().encode(text).length > 20480) throw new Error("JSON слишком большой: максимум 20 КиБ.");
  let value: Record<string, unknown>;
  try { value = JSON.parse(text); } catch { throw new Error("Некорректный JSON учётных записей ACME-DNS."); }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Нужен JSON учётных записей ACME-DNS.");
  if (typeof value.username === "string") {
    if (names.length !== 1) throw new Error("Для нескольких доменов нужен JSON с отдельной записью для каждого имени.");
    value = { [names[0]]: value };
  }
  if (names.length > 10 || Object.keys(value).length !== names.length || names.some(name => !dnsName.test(name) || !Object.hasOwn(value, name))) {
    throw new Error("В JSON должны быть только домены этого сертификата, без префикса *.");
  }
  const targets = new Set<string>();
  const accounts: Record<string, AcmeDNSAccount> = {};
  for (const name of names) {
    const entry = value[name] as AcmeDNSAccount | undefined;
    if (!entry || typeof entry !== "object" || ![entry.username, entry.password, entry.subdomain, entry.fulldomain].every(item => typeof item === "string" && item.length > 0)
      || !/^[a-zA-Z0-9_-]{1,128}$/.test(entry.username) || entry.password.length > 512 || entry.password.trim() !== entry.password || /[\r\n\x00]/.test(entry.password)
      || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(entry.subdomain)
      || entry.fulldomain.length > 253 || !dnsName.test(entry.fulldomain) || !entry.fulldomain.startsWith(`${entry.subdomain}.`)
      || targets.has(entry.fulldomain)) throw new Error("Проверьте username, password, subdomain и fulldomain; каждому имени нужна отдельная запись.");
    targets.add(entry.fulldomain);
    accounts[name] = { username: entry.username, password: entry.password, subdomain: entry.subdomain, fulldomain: entry.fulldomain };
  }
  return JSON.stringify(accounts);
}

export function acmeDNSDelegations(accounts: string): AcmeDNSDelegation[] {
  try {
    return Object.entries(JSON.parse(accounts) as Record<string, AcmeDNSAccount>)
      .map(([domain, account]) => ({ domain, name: `_acme-challenge.${domain}`, target: account.fulldomain }));
  } catch { return []; }
}
