type QualityNode = {
  selected: boolean;
  inRuntimePool: boolean;
  available: boolean;
  quality: boolean;
  availability: number | null;
  loss: number | null;
  speedBps: number | null;
  p95: number | null;
  median: number | null;
  decisionMedian: number | null;
  label: string;
};

function responsiveScoreOrder(left: QualityNode, right: QualityNode): number {
  const leftDelay = left.decisionMedian ?? left.median ?? left.p95 ?? 0;
  const rightDelay = right.decisionMedian ?? right.median ?? right.p95 ?? 0;
  const leftMeasured = (left.speedBps ?? 0) > 0 && leftDelay > 0;
  const rightMeasured = (right.speedBps ?? 0) > 0 && rightDelay > 0;
  if (leftMeasured !== rightMeasured) return leftMeasured ? -1 : 1;
  if (!leftMeasured || !rightMeasured) return 0;
  const leftScore = (left.speedBps ?? 0) * rightDelay;
  const rightScore = (right.speedBps ?? 0) * leftDelay;
  return rightScore - leftScore;
}

export function qualitySheet<T extends QualityNode>(
  policies: { key: string; name: string; nodeStats: T[] }[],
  selectedKey: string,
) {
  // IDs, not tab positions: refreshes and reordering must keep the chosen sheet.
  const policy = policies.find((item) => item.key === selectedKey) ?? policies[0];
  const rows = [...(policy?.nodeStats ?? [])].sort((left, right) => {
    if (left.selected !== right.selected) return left.selected ? -1 : 1;
    // Keep the live working reserves next to the active node. Historical
    // availability still ranks the remaining background candidates.
    if (left.inRuntimePool !== right.inRuntimePool) return left.inRuntimePool ? -1 : 1;
    if (left.available !== right.available) return left.available ? -1 : 1;
    if (left.quality !== right.quality) return left.quality ? -1 : 1;
    return responsiveScoreOrder(left, right)
      || (right.availability ?? -1) - (left.availability ?? -1)
      || (left.loss ?? 101) - (right.loss ?? 101)
      || (right.speedBps ?? -1) - (left.speedBps ?? -1)
      || (left.p95 ?? Number.MAX_SAFE_INTEGER) - (right.p95 ?? Number.MAX_SAFE_INTEGER)
      || (left.median ?? Number.MAX_SAFE_INTEGER) - (right.median ?? Number.MAX_SAFE_INTEGER)
      || left.label.localeCompare(right.label, "ru");
  }).map((node, index) => ({ ...node, rank: index + 1 }));
  return { policy, total: rows.length, rows: rows.slice(0, 10) };
}
