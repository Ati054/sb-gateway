import assert from "node:assert/strict";
import test from "node:test";
import { mergeOverviewState } from "../app/overview-state.ts";

test("temporary inventory failures retain only the displayed LAN links", () => {
  const previous = { connection_address: { state: "ready", inventory_ready: true, address: "198.51.100.8", interface: "wan", wan_addresses: [{ address: "198.51.100.8" }], local_addresses: [{ address: "192.0.2.1", interface: "lan" }] } };
  const incoming = { active_revision: "new", connection_address: { state: "unavailable", address: "", interface: "" } };
  const result = mergeOverviewState(previous, incoming);
  assert.equal(result.active_revision, "new");
  assert.deepEqual(result.connection_address.local_addresses, previous.connection_address.local_addresses);
  assert.equal(result.connection_address.state, "unavailable");
  assert.equal(result.connection_address.inventory_ready, undefined);
  assert.equal(result.connection_address.address, "");
  assert.equal(result.connection_address.wan_addresses, undefined);
  assert.equal(incoming.connection_address.local_addresses, undefined);
});

test("a complete inventory can remove or replace old LAN links", () => {
  const previous = { connection_address: { local_addresses: [{ address: "192.0.2.1" }] } };
  for (const local_addresses of [[], [{ address: "192.0.2.2" }]]) {
    const incoming = { connection_address: { inventory_ready: true, local_addresses } };
    assert.equal(mergeOverviewState(previous, incoming), incoming);
  }
  const empty = { connection_address: { state: "unavailable" } };
  assert.equal(mergeOverviewState(undefined, empty), empty);
});
