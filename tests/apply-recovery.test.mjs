import assert from "node:assert/strict";
import test from "node:test";
import { recoveredApplyConfirmed } from "../app/apply-recovery.ts";

test("a committed revision alone cannot confirm a disconnected Apply", () => {
  const completed = { active_revision: "target", apply_pending: false };
  const ready = { traffic_ready: true };
  assert.equal(recoveredApplyConfirmed("target", completed, ready), true);
  for (const status of [
    { active_revision: "target", apply_pending: true },
    { active_revision: "target" },
    { active_revision: "previous", apply_pending: false },
  ]) assert.equal(recoveredApplyConfirmed("target", status, ready), false);
  assert.equal(recoveredApplyConfirmed("target", completed, { traffic_ready: false }), false);
  assert.equal(recoveredApplyConfirmed("target", completed, { ready: true }), false);
  assert.equal(recoveredApplyConfirmed("", completed, ready), false);
});
