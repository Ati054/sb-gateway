export interface WatchdogSettings {
  interval: number;
  failures: number;
  recoveries: number;
  cooldown: number;
  restarts: number;
}

export function validWatchdogSettings(values: WatchdogSettings): boolean {
  const ranges: Array<[number, number, number]> = [
    [values.interval, 5, 300],
    [values.failures, 1, 20],
    [values.recoveries, 1, 20],
    [values.cooldown, 0, 3600],
    [values.restarts, 1, 60],
  ];
  return ranges.every(([value, minimum, maximum]) =>
    Number.isInteger(value) && value >= minimum && value <= maximum,
  );
}
