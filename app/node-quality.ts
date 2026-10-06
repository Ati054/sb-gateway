type QualityNode = {
  id: string;
  selected: boolean;
  inRuntimePool: boolean;
  available: boolean;
  unstable?: boolean;
  quality: boolean;
  availability: number | null;
  loss: number | null;
  median: number | null;
  label: string;
};

// A brief failed probe is shown by the live status marker, not as a severe
// route warning over the historical availability column.
export function confirmedUnstableRoute(
  availabilityOK: boolean | undefined,
  samples: number,
  lossPercent: number | null,
  maxPacketLossPercent: number,
): boolean {
  return availabilityOK === false && samples >= 10 &&
    lossPercent !== null && lossPercent > maxPacketLossPercent;
}

function latencyOrder(left: QualityNode, right: QualityNode): number {
  const leftDelay = left.median !== null && Number.isFinite(left.median) ? left.median : Number.MAX_SAFE_INTEGER;
  const rightDelay = right.median !== null && Number.isFinite(right.median) ? right.median : Number.MAX_SAFE_INTEGER;
  return leftDelay - rightDelay;
}

export function qualitySheet<T extends QualityNode>(
  policies: {
    key: string;
    name: string;
    mode?: "best" | "priority";
    priorityOrder?: string[];
    nodeStats: T[];
  }[],
  selectedKey: string,
) {
  // IDs, not tab positions: refreshes and reordering must keep the chosen sheet.
  const policy = policies.find((item) => item.key === selectedKey) ?? policies[0];
  const sourceRows = policy?.nodeStats ?? [];
  const sourcePositions = new Map(sourceRows.map((node, index) => [node.id, index]));
  const priorityPositions = new Map((policy?.priorityOrder ?? []).map((id, index) => [id, index]));
  const rows = [...sourceRows].sort((left, right) => {
    if (policy?.mode === "priority") {
      const leftPosition = priorityPositions.get(left.id);
      const rightPosition = priorityPositions.get(right.id);
      if (leftPosition != null || rightPosition != null) {
        if (leftPosition == null) return 1;
        if (rightPosition == null) return -1;
        if (leftPosition !== rightPosition) return leftPosition - rightPosition;
      }
      return (sourcePositions.get(left.id) ?? 0) - (sourcePositions.get(right.id) ?? 0);
    }
    if (left.selected !== right.selected) return left.selected ? -1 : 1;
    // A historical table sorts by its visible median, not the controller's
    // latest decision sample or hidden shortlist membership.
    const latency = latencyOrder(left, right);
    if (latency) return latency;
    if (left.available !== right.available) return left.available ? -1 : 1;
    if (Boolean(left.unstable) !== Boolean(right.unstable)) return left.unstable ? 1 : -1;
    if (left.quality !== right.quality) return left.quality ? -1 : 1;
    return (right.availability ?? -1) - (left.availability ?? -1)
      || (left.loss ?? 101) - (right.loss ?? 101)
      || left.label.localeCompare(right.label, "ru");
  }).map((node, index) => ({
    ...node,
    rank: policy?.mode === "priority" && priorityPositions.has(node.id)
      ? (priorityPositions.get(node.id) ?? index) + 1
      : index + 1,
  }));
  return { policy, total: rows.length, rows: rows.slice(0, 10) };
}
