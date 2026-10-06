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

export function activeQualityMetrics(rawHealth: unknown, candidate: string, since = 0) {
  const health = rawHealth && typeof rawHealth === "object"
    ? rawHealth as Record<string, unknown> : {};
  const valueAt = (key: string) => {
    const values = health[key];
    return values && typeof values === "object"
      ? (values as Record<string, unknown>)[candidate] : undefined;
  };
  const positive = (value: unknown) => typeof value === "number" && Number.isFinite(value) && value > 0 ? value : null;
  const medianAt = positive(valueAt("last_good_at"));
  const median = medianAt !== null && medianAt >= since ? positive(valueAt("median_delay_ms")) : null;
  return { median, medianAt: median === null ? null : medianAt };
}

export function freshLatencyComparison(rawHealth: unknown, candidate: string, now: number, since = 0) {
  const health = rawHealth && typeof rawHealth === "object"
    ? rawHealth as Record<string, unknown> : {};
  const comparisons = health.latency_comparisons;
  const raw = comparisons && typeof comparisons === "object"
    ? (comparisons as Record<string, unknown>)[candidate] : null;
  if (health.runtime_confirmed !== true || health.runtime_error || candidate === health.runtime_selected
    || !raw || typeof raw !== "object") return null;
  const pair = raw as Record<string, unknown>;
  const numbers = [pair.active_delay_ms, pair.candidate_delay_ms, pair.active_at, pair.candidate_at, pair.expires_at];
  if (!numbers.every(value => typeof value === "number" && Number.isFinite(value) && value > 0)
    || !Number.isFinite(now) || pair.active !== health.runtime_selected || pair.active === "block") return null;
  const [active, reserve, activeAt, candidateAt, expires] = numbers as number[];
  if (activeAt < since || candidateAt < since || activeAt > now || candidateAt > now
    || expires <= now || expires <= Math.max(activeAt, candidateAt)) return null;
  const percent = roundOne((reserve - active) * 100 / active);
  if (!Number.isFinite(percent)) return null;
  return { percent: Object.is(percent, -0) ? 0 : percent, activeAt, candidateAt };
}
