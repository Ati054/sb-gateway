type JsonRecord = Record<string, unknown>;

const hostnamePattern = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

function metadata(profile: unknown): JsonRecord {
  if (!profile || typeof profile !== "object" || Array.isArray(profile)) return {};
  const value = (profile as JsonRecord).certificate_metadata;
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as JsonRecord)
    : {};
}

function profileRecord(profile: unknown): JsonRecord {
  return profile && typeof profile === "object" && !Array.isArray(profile)
    ? (profile as JsonRecord)
    : {};
}

function profileID(profile: unknown): string {
  const id = profileRecord(profile).id;
  return typeof id === "string" ? id.trim() : "";
}

export function canonicalConcreteHostname(value: unknown): string {
  if (typeof value !== "string") return "";
  const hostname = value.trim().replace(/\.+$/, "").toLowerCase();
  const labels = hostname.split(".");
  if (
    labels.length === 4 &&
    labels.every((label) => /^\d+$/.test(label) && Number(label) <= 255)
  ) return "";
  return hostnamePattern.test(hostname) ? hostname : "";
}

function canonicalCertificateName(value: unknown): string {
  if (typeof value !== "string") return "";
  const name = value.trim().replace(/\.+$/, "").toLowerCase();
  if (name.startsWith("*.")) {
    const suffix = canonicalConcreteHostname(name.slice(2));
    return suffix ? `*.${suffix}` : "";
  }
  return canonicalConcreteHostname(name);
}

function certificateDnsNames(profile: unknown): string[] {
  const names = metadata(profile).dns_names;
  return Array.isArray(names) ? names.map(canonicalCertificateName).filter(Boolean) : [];
}

export function tlsConcreteHostnames(profile: unknown): string[] {
  return [...new Set(certificateDnsNames(profile).filter((name) => !name.startsWith("*.")))];
}

export function certificateCoversHostname(profile: unknown, value: unknown): boolean {
  const hostname = canonicalConcreteHostname(value);
  if (!hostname) return false;
  return certificateDnsNames(profile).some((name) => {
    if (name === hostname) return true;
    if (!name.startsWith("*.")) return false;
    const suffix = name.slice(2);
    if (!hostname.endsWith(`.${suffix}`)) return false;
    const prefix = hostname.slice(0, -(suffix.length + 1));
    return Boolean(prefix) && !prefix.includes(".");
  });
}

// Prefer one provable certificate for a typed SNI. A generated certificate is
// stronger evidence than an unissued local-CA target, and an exact SAN is
// stronger than a wildcard. Ambiguous matches never replace the current choice.
export function tlsProfileIdForHostname(
  profiles: unknown,
  value: unknown,
  currentProfileId: unknown,
): string {
  const current = typeof currentProfileId === "string" ? currentProfileId : "";
  const hostname = canonicalConcreteHostname(value);
  if (!hostname || !Array.isArray(profiles)) return current;
  const eligible = profiles.filter((profile) => {
    const record = profileRecord(profile);
    return record.enabled !== false && Boolean(profileID(record));
  });
  const choose = (matches: unknown[]): string | undefined => {
    if (matches.length === 1) return profileID(matches[0]);
    if (matches.some((profile) => profileID(profile) === current)) return current;
    return matches.length ? current : undefined;
  };
  const exactCertificate = eligible.filter((profile) =>
    tlsConcreteHostnames(profile).includes(hostname),
  );
  const exactCertificateChoice = choose(exactCertificate);
  if (exactCertificateChoice !== undefined) return exactCertificateChoice;
  const localCATarget = eligible.filter(
    (profile) =>
      canonicalConcreteHostname(profileRecord(profile).local_ca_server_name) ===
      hostname,
  );
  const localCAChoice = choose(localCATarget);
  if (localCAChoice !== undefined) return localCAChoice;
  const coveringCertificate = eligible.filter((profile) =>
    certificateCoversHostname(profile, hostname),
  );
  return choose(coveringCertificate) ?? current;
}

// A user-triggered TLS change makes a sole concrete SAN the new endpoint name.
// Ambiguous certificates retain only a currently covered concrete hostname.
export function hostnameAfterTLSProfileChange(profile: unknown, current: unknown): string {
  const candidates = tlsConcreteHostnames(profile);
  if (candidates.length === 1) return candidates[0];
  if (!certificateDnsNames(profile).length) {
    return typeof current === "string" ? current : "";
  }
  return certificateCoversHostname(profile, current)
    ? canonicalConcreteHostname(current)
    : "";
}

export function cdnDeploymentAfterTLSProfileChange(
  deployment: JsonRecord,
  profileId: string,
  profile: unknown,
): JsonRecord {
  return {
    ...deployment,
    tls_profile_id: profileId,
    origin_server_name: hostnameAfterTLSProfileChange(
      profile,
      deployment.origin_server_name,
    ),
  };
}

export function cdnDeploymentForTLSInitialization(
  deployment: JsonRecord,
  profile: unknown,
): JsonRecord {
  if (typeof deployment.origin_server_name === "string" && deployment.origin_server_name.trim()) {
    return deployment;
  }
  const candidates = tlsConcreteHostnames(profile);
  return candidates.length === 1
    ? { ...deployment, origin_server_name: candidates[0] }
    : deployment;
}

// Initialization never overwrites an explicitly persisted hostname.
export function hostnameForTLSProfileInitialization(
  profile: unknown,
  current: unknown,
  mayAutofill: boolean,
): string {
  if (!mayAutofill) return typeof current === "string" ? current : "";
  const candidates = tlsConcreteHostnames(profile);
  return candidates.length === 1 ? candidates[0] : typeof current === "string" ? current : "";
}

// Config refreshes must not replace an operator's open endpoint draft.
export function subscriptionEndpointValueAfterConfigRefresh<T>(
  current: T,
  incoming: T,
  dialogOpen: boolean,
): T {
  return dialogOpen ? current : incoming;
}

export function subscriptionEndpointUsesTLSHostname(mode: unknown): boolean {
  return mode === "direct" || mode === "direct-and-cdn";
}
