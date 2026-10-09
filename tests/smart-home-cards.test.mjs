import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import test from "node:test";

test("smart-home cards stay separate, bounded and available in the panel", async () => {
 const catalog=JSON.parse(await readFile(new URL("../internal/rulesets/service-packs.json", import.meta.url), "utf8"));
 const page=await readFile(new URL("../app/page.tsx", import.meta.url), "utf8");
 const ids=["ewelink", "xiaomi-home", "tuya", "aqara", "shelly"];
 const seen=new Set();
 for(const id of ids){
  const pack=catalog.find(p=>p.id===id);
  assert.ok(pack);
  assert.equal(pack.category, "Умный дом");
  assert.equal(pack.always_direct, false);
  assert.equal(pack.update_mode, "official");
  assert.equal(pack.upstream_name, null);
  assert.deepEqual(pack.included_pack_ids, []);
  for(const field of ["ip_cidrs", "tcp_ports", "tcp_port_ranges", "udp_ports", "udp_port_ranges", "sniffed_protocols"]) assert.deepEqual(pack[field], []);
  assert.ok(page.includes(`id: "${id}", name: "${pack.name}"`));
  for(const domain of pack.fallback_domains){
   assert.ok(!seen.has(domain), "ecosystems unexpectedly overlap");
   seen.add(domain);
   assert.ok(!["amazonaws.com", "google.com", "googleapis.com", "cloudfront.net", "mi.com", "xiaomi.com", "local"].includes(domain));
  }
 }
});
