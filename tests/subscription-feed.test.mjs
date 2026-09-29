import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { subscriptionFeedGroups } from "../app/subscription-feed.ts";
import { normalizeLocalizedSource } from "./source-localization.mjs";

test("subscription view preserves provider and node order without sorting names", () => {
  const nodes = [
    { subscription_id: "b", subscription_display_name: "B", label: "Zeta" },
    { subscription_id: "b", subscription_display_name: "B", label: "Alpha" },
    { subscription_id: "a", subscription_display_name: "A", label: "Beta" },
  ];
  const feeds = subscriptionFeedGroups(nodes);
  assert.deepEqual(feeds.map((feed) => feed.id), ["b", "a"]);
  assert.deepEqual(feeds[0].nodes, nodes.slice(0, 2));
  assert.deepEqual(feeds[1].nodes, nodes.slice(2));
});

test("subscription view is a presentation toggle and keeps the shared selection", async () => {
  const page = normalizeLocalizedSource(await readFile(new URL("../app/page.tsx", import.meta.url), "utf8"));
  const picker = page.slice(page.indexOf("function SubscriptionLocationPicker("), page.indexOf("function resultRows("));
  assert.match(picker, /nodeView === "subscription" \? subscriptionFeeds\.map/);
  assert.match(picker, /checked=\{checked\}/);
  assert.match(picker, /toggleLocation\(country, key\)/);
  assert.doesNotMatch(picker, /setNodeView\([^)]*\);\s*(?:onSelectionOrderChange|onLocationsChange)/);
});
