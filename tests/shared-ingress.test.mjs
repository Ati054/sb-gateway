import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { normalizeLocalizedSource } from "./source-localization.mjs";

test("shared TCP 443 is opt-in and round-trips through Settings", async () => {
 const defaults=JSON.parse(await readFile(new URL("../internal/controlplane/default-config.json",import.meta.url),"utf8"));
 assert.equal(defaults.public_exposure.shared_tcp_443,false);
 const page=normalizeLocalizedSource(await readFile(new URL("../app/page.tsx",import.meta.url),"utf8"));
 assert.match(page,/useState\(exposureFromDraft.shared_tcp_443 === true\)/);
 assert.match(page,/shared_tcp_443: sharedTcp443/);
 assert.match(page,/checked=\{sharedTcp443\}[\s\S]*?onChange=\{setSharedTcp443\}[\s\S]*?label="Общий TCP 443 для Reality и HTTPS"/);
 const bootstrap=await readFile(new URL("../scripts/render-runtime.sh",import.meta.url),"utf8");
 for(const variable of ["SHARED_STREAM","ORIGIN_MAPS"]) assert.ok(bootstrap.includes(`\${${variable}}`));
});
