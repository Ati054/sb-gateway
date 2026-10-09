import assert from "node:assert/strict";
import test from "node:test";
import {DraftAutosave} from "../app/draft-autosave.ts";

function fixture(save) {
  const pending = [], saving = [], errors = [];
  const autosave = new DraftAutosave({
    save, delayMs: 60_000,
    onPending: value => pending.push(value),
    onSaving: value => saving.push(value),
    onError: error => errors.push(error),
  });
  return {autosave, pending, saving, errors};
}

test("idle draft autosave waits for the last edit and never applies runtime", async (context) => {
  context.mock.timers.enable({apis: ["setTimeout"]});
  let calls = 0;
  const state = fixture(async () => {calls++;});
  state.autosave.update();
  context.mock.timers.tick(59_999);
  assert.equal(calls, 0);
  state.autosave.update();
  context.mock.timers.tick(59_999);
  assert.equal(calls, 0);
  context.mock.timers.tick(1);
  await state.autosave.flush();
  assert.equal(calls, 1);
  assert.equal(state.autosave.pending, false);
  state.autosave.dispose();
});

test("draft edits coalesce; navigation and Apply share the same flush", async () => {
  let calls = 0, release;
  const gate = new Promise(resolve => {release = resolve;});
  const state = fixture(async () => {calls++; await gate;});
  state.autosave.update();
  state.autosave.update();
  const navigation = state.autosave.flush();
  const apply = state.autosave.flush();
  assert.equal(navigation, apply);
  await Promise.resolve();
  assert.equal(calls, 1);
  assert.equal(state.autosave.pending, true);
  release();
  await navigation;
  assert.equal(state.autosave.pending, false);
  assert.deepEqual(state.saving, [true, false]);
  await state.autosave.flush();
  assert.equal(calls, 1);
  state.autosave.dispose();
});

test("an edit during a draft write is saved before navigation completes", async () => {
  let release, calls = 0, current = "first";
  const gate = new Promise(resolve => {release = resolve;});
  const values = [];
  const state = fixture(async () => {
    calls++; values.push(current);
    if (calls === 1) await gate;
  });
  state.autosave.update();
  const navigation = state.autosave.flush();
  await Promise.resolve();
  current = "second";
  state.autosave.update();
  release();
  await navigation;
  assert.deepEqual(values, ["first", "second"]);
  assert.equal(state.autosave.pending, false);
  state.autosave.dispose();
});

test("failed saving keeps the edit pending and rejects navigation or Apply", async () => {
  let fail = true;
  const state = fixture(async () => {if (fail) throw new Error("offline");});
  state.autosave.update();
  await assert.rejects(state.autosave.flush(), /offline/);
  assert.equal(state.autosave.pending, true);
  assert.equal(state.errors.length, 1);
  fail = false;
  await state.autosave.flush();
  assert.equal(state.autosave.pending, false);
  state.autosave.dispose();
});

test("reset cancels unpersisted edits without issuing a draft write", async () => {
  let calls = 0;
  const state = fixture(async () => {calls++;});
  state.autosave.update();
  state.autosave.discard();
  await state.autosave.flush();
  assert.equal(calls, 0);
  assert.equal(state.autosave.pending, false);
  state.autosave.dispose();
});

test("reset cannot race an in-flight draft write", async () => {
  let release;
  const gate = new Promise(resolve => {release = resolve;});
  const state = fixture(() => gate);
  state.autosave.update();
  const saving = state.autosave.flush();
  assert.throws(() => state.autosave.discard(), /in progress/);
  release();
  await saving;
  state.autosave.discard();
  state.autosave.dispose();
});
