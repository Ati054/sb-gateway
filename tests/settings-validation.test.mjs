import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { validWatchdogSettings } from "../app/settings-validation.ts";

const defaults = JSON.parse(await readFile(new URL("../internal/controlplane/default-config.json", import.meta.url), "utf8")).watchdog;
const values = {
  interval: defaults.interval_seconds,
  failures: defaults.failure_threshold,
  recoveries: defaults.recovery_threshold,
  cooldown: defaults.recovery_cooldown_seconds,
  restarts: defaults.max_restarts_per_hour,
};

test("settings save accepts the shipped zero-cooldown configuration", () => {
  assert.equal(values.cooldown, 0);
  assert.equal(validWatchdogSettings(values), true);
  for (let cooldown = 0; cooldown < 10; cooldown++) {
    assert.equal(validWatchdogSettings({...values, cooldown}), true);
  }
});

test("settings validation preserves all field boundaries and rejects non-integers", () => {
  for (const [key, min, max] of [["interval", 5, 300], ["failures", 1, 20], ["recoveries", 1, 20], ["cooldown", 0, 3600], ["restarts", 1, 60]]) {
    for (const value of [min, max]) assert.equal(validWatchdogSettings({...values, [key]: value}), true, `${key}=${value}`);
    for (const value of [min - 1, max + 1, min + 0.5, NaN, Infinity]) {
      assert.equal(validWatchdogSettings({...values, [key]: value}), false, `${key}=${value}`);
    }
  }
});
