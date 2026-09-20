type QualityNode = {
  id: string;
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
    // URLTest is a quality ranking: keep live reserves next to the active node,
    // then rank the remaining background candidates by measured responsiveness.
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
  }).map((node, index) => ({
    ...node,
    rank: policy?.mode === "priority" && priorityPositions.has(node.id)
      ? (priorityPositions.get(node.id) ?? index) + 1
      : index + 1,
  }));
  return { policy, total: rows.length, rows: rows.slice(0, 10) };
}
