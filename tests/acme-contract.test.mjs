import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import test from "node:test";
import ts from "typescript";

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

test("saving an unchanged ACME form retains the pending status confirmed by the server", async () => {
 const source=await readFile("app/acme-fields.tsx","utf8");
 const parsed=ts.createSourceFile("acme-fields.tsx",source,ts.ScriptTarget.Latest,true,ts.ScriptKind.TSX);
 const names=new Set(["canonicalAcmeDomains","sameAcmeDomains","acmeIssueAvailable","useAcmeProfile"]);
 const extracted=parsed.statements.filter(node=>ts.isFunctionDeclaration(node)&&names.has(node.name?.text)||ts.isVariableStatement(node)&&node.declarationList.declarations.some(d=>d.name.getText(parsed)==="defaults"))
  .map(node=>node.getText(parsed).replace(/^export /,"")).join("\n");
 const compiled=ts.transpileModule(extracted,{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText;
 for(const state of ["queued","running"]){
  const slots=[];let index=0;
  const useState=initial=>{const slot=index++;slots[slot]=slot===4?true:initial;return [slots[slot],update=>{slots[slot]=typeof update==="function"?update(slots[slot]):update}];};
  const message=state==="queued"?"Выпуск поставлен в очередь.":"Проверка DNS и выпуск сертификата…";
  const configure=async()=>({saved:true,state,message});
  const hook=new Function("useState","useEffect","configureAcme","getAcmeStatus","acmeDNSDelegations",`${compiled};return useAcmeProfile;`)(useState,()=>{},configure,()=>{},()=>[]);
  await hook("prepared-tls","acme").save("prepared-tls",false);
  assert.equal(slots[3].state,state);
  assert.equal(slots[3].message,message);
  assert.notEqual(slots[3].message,"Настройки сохранены.");
 }
});
