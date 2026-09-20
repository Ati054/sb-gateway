import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import test from "node:test";

test("ACME ships as a separate bounded worker and never exposes DNS credentials",async()=>{
 const docker=await readFile("Dockerfile","utf8");
 const manager=await readFile("internal/controlplane/acme.go","utf8");
 assert.match(docker,/COPY --from=sb-gateway-build \/out\/sb-acme \/usr\/local\/bin\/sb-acme/);
 assert.match(manager,/GOMAXPROCS=1/);assert.match(manager,/GOMEMLIMIT=48MiB/);
 assert.match(manager,/acmeMu.TryLock/);assert.match(manager,/command.Stdin = bytes.NewReader/);
 assert.doesNotMatch(manager,/controller.Restart|applyConfiguration\(/);
});
test("TLS profile exposes ACME without hardcoding the deployment's domain names",async()=>{
 const page=await readFile("app/page.tsx","utf8");
 const fields=await readFile("app/acme-fields.tsx","utf8");
 assert.match(page,/<AcmeFields model={acme}/);
 assert.match(page,/Выпустить сертификат/);
 for(const provider of ["gcore","regru","cloudflare"])assert.ok(fields.includes(`value="${provider}"`));
 assert.match(fields,/type="password"/);assert.match(fields,/terms_accepted/);
 assert.doesNotMatch(fields,/Провайдер DNS-записей, не CDN/);
});
test("TLS profile exposes a first-class local CA mode with explicit rotation",async()=>{
 const page=await readFile("app/page.tsx","utf8");
 const hook=await readFile("app/acme-fields.tsx","utf8");
 assert.match(page,/<option value="local-ca">/);
 assert.match(page,/name="local_ca_server_name"/);
 assert.match(page,/generate_local_ca: generateLocalCA/);
 assert.match(page,/data-generate-local-ca="true"/);
 assert.match(page,/regenerateLocalCA \|\| !localCAPairReady/);
 assert.match(hook,/mode !== "acme"/);
});
