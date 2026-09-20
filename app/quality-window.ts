export type WindowedQualityStats = {
  samples: number;
  successes: number;
  failures: number;
  loss_percent: number | null;
  availability_percent: number | null;
  median_ms: number | null;
  p95_ms: number | null;
};

function roundOne(value: number): number {
  return Math.round(value * 10) / 10;
}

function summarizeSamples(raw: unknown, since: number): WindowedQualityStats {
  const samples = Array.isArray(raw)
    ? raw.filter((entry) => {
        if (!entry || typeof entry !== "object") return false;
        const at = Number((entry as Record<string, unknown>).at);
        return Number.isFinite(at) && at >= since;
      })
    : [];
  const delays: number[] = [];
  let failures = 0;
  for (const entry of samples) {
    const sample = entry as Record<string, unknown>;
    const delay = Number(sample.delay_ms);
    if (sample.ok === true && Number.isFinite(delay)) {
      delays.push(Math.trunc(delay));
    } else {
      failures += 1;
    }
  }
  delays.sort((left, right) => left - right);
  const successes = delays.length;
  const middle = Math.floor(delays.length / 2);
  const median = !delays.length
    ? null
    : delays.length % 2
      ? delays[middle]
      : Math.trunc((delays[middle - 1] + delays[middle]) / 2);
  const p95Index = delays.length
    ? Math.ceil((delays.length - 1) * 0.95)
    : -1;
  return {
    samples: samples.length,
    successes,
    failures,
    loss_percent: samples.length ? roundOne((failures * 100) / samples.length) : null,
    availability_percent: samples.length ? roundOne((successes * 100) / samples.length) : null,
    median_ms: median,
    p95_ms: p95Index >= 0 ? delays[p95Index] : null,
  };
}

export function qualityStatsSince(
  rawDailySamples: unknown,
  candidateIds: string[],
  since: number,
): Record<string, WindowedQualityStats> {
  const dailySamples = rawDailySamples && typeof rawDailySamples === "object"
    ? rawDailySamples as Record<string, unknown>
    : {};
  return Object.fromEntries(
    candidateIds.map((candidate) => [candidate, summarizeSamples(dailySamples[candidate], since)]),
  );
}

export function latestSpeedSince(
  rawSamples: unknown,
  rawLastProbeAt: unknown,
  candidate: string,
  since: number,
): number | null {
  const lastProbeAt = rawLastProbeAt && typeof rawLastProbeAt === "object"
    ? Number((rawLastProbeAt as Record<string, unknown>)[candidate])
    : 0;
  if (!Number.isFinite(lastProbeAt) || lastProbeAt < since) return null;
  const values = rawSamples && typeof rawSamples === "object"
    ? (rawSamples as Record<string, unknown>)[candidate]
    : undefined;
  if (!Array.isArray(values)) return null;
  for (let index = values.length - 1; index >= 0; index -= 1) {
    const value = Number(values[index]);
    if (Number.isFinite(value) && value > 0) return value;
  }
  return null;
}
