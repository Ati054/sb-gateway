import assert from "node:assert/strict";
import test from "node:test";
import { memoryMiB, validMemoryMiB } from "../app/container-memory-settings.ts";

test("memory fields read actual RouterOS binary units, not fallback draft values", () => {
  for (const [value, expected] of [["224.0MiB","224"],[268435456,"256"],["402653184","384"],["1.5GiB","1536"],[null,""],["unlimited",""],[true,""]]) assert.equal(memoryMiB(value),expected);
});

test("both limits require explicit integer values in the correct order", () => {
  assert.equal(validMemoryMiB("224","256"),true);
  for (const pair of [["320","256"],["15","256"],["224","8193"],["224.5","256"],["","256"],["224","2e3"]]) assert.equal(validMemoryMiB(...pair),false);
});
