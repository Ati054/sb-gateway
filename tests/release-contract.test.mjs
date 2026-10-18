import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("installation guides match the release and include storage-aware startup", async () => {
  const { version } = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
  for (const file of ["INSTALL.md", "INSTALL-RU.md"]) {
    const source = await readFile(new URL("../docs/" + file, import.meta.url), "utf8");
    assert.ok(source.includes("sb-gateway-" + version + "-routeros-bundle.zip"), file);
    assert.ok(source.includes("sb-gateway-" + version + "-linux-arm64.tar"), file);
    for (const referenced of source.matchAll(/sb-gateway-([0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[0-9]+)?)-(?:routeros-bundle|linux-arm64)/g)) {
      assert.equal(referenced[1], version, file + ": stale release reference");
    }
    assert.match(source, /  bootstrap\.rsc\r?\n  container-startup\.rsc/);
  }
});

test("release toolchains agree and shared-core compression is pinned", async () => {
  const dockerfile = await readFile(new URL("../Dockerfile", import.meta.url), "utf8");
  const workflow = await readFile(new URL("../.github/workflows/release-hygiene.yml", import.meta.url), "utf8");
  const moduleSource = await readFile(new URL("../go.mod", import.meta.url), "utf8");
  const shared = await readFile(new URL("../scripts/prepare-xray-multicall.sh", import.meta.url), "utf8");
  const pins = [...dockerfile.matchAll(/ARG (?:XRAY_)?GO_IMAGE=golang:(\d+\.\d+\.\d+)-alpine@sha256:[a-f0-9]{64}/g)];
  assert.equal(pins.length, 2);
  assert.equal(pins[0][1], pins[1][1]);
  assert.ok(moduleSource.includes("toolchain go" + pins[0][1]));
  const ci = [...workflow.matchAll(/go-version: '(\d+\.\d+\.\d+)'/g)];
  assert.equal(ci.length, 2);
  for (const pin of ci) assert.equal(pin[1], pins[0][1]);
  assert.match(shared, /-require=github\.com\/klauspost\/compress@v1\.18\.7/);
});

test("release packaging accepts numbered RCs without accepting unsafe versions", async () => {
  for (const file of ["package-github-release.ps1", "export-public-source.ps1", "prepare-public-repository.ps1"]) {
    const source = await readFile(new URL("../scripts/" + file, import.meta.url), "utf8");
    const match = source.match(/\$version -notmatch '([^']+)'/);
    assert.ok(match, "Missing version guard in " + file);
    const guard = new RegExp(match[1]);
    for (const version of ["1.6.44", "1.6.44-rc.1", "1.6.44-rc.12"]) assert.ok(guard.test(version), file + ": " + version);
    for (const version of ["1.6.44-rc.0", "1.6.44-rc", "1.6.44/../x", "1.6.44;exec"]) assert.ok(!guard.test(version), file + ": " + version);
  }
});

test("release image declares the in-place update contract", async () => {
  const dockerfile = await readFile(new URL("../Dockerfile", import.meta.url), "utf8");
  assert.match(dockerfile, /io\.sb-gateway\.lifecycle\.version="1"/);
  assert.match(dockerfile, /io\.sb-gateway\.config\.schema="1"/);
  assert.match(dockerfile, /io\.sb-gateway\.config\.minimum-schema="1"/);
});

test("public changelog preserves the reviewed history rather than exporting the internal journal", async () => {
  const source = await readFile(new URL("../scripts/export-public-source.ps1", import.meta.url), "utf8");
  const match = source.match(/if \(\$_ -match '([^']+)'\)/);
  assert.ok(match, "Missing changelog boundary guard");
  const guard = new RegExp(match[1]);
  for (const heading of ["## 1.6.43", "## 1.6.44-rc.2", "## 1.6.44-rc.12"]) assert.ok(guard.test(heading), heading);
  for (const heading of ["### Changes", "## 1.6.44-rc.0", "## 1.6.44-rc"]) assert.ok(!guard.test(heading), heading);
  assert.match(source, /docs\/PUBLIC-CHANGELOG\.md/);
  assert.match(source, /\[System\.IO\.File\]::Copy\(\$publicChangelogPath,/);
  assert.doesNotMatch(source, /\$changelogLines\[\$start\.\./);
  const history = await readFile(new URL("../docs/PUBLIC-CHANGELOG.md", import.meta.url), "utf8");
  const versions = [...history.matchAll(new RegExp(guard.source, "gm"))].map(match => match[1]);
  const pkg = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
  assert.equal(versions[0], pkg.version);
  assert.ok(versions.length > 1);
  assert.equal(new Set(versions).size, versions.length);
  for (const version of [
    "1.6.17", "1.6.18", "1.6.19", "1.6.20", "1.6.21", "1.6.22",
    "1.6.24", "1.6.25", "1.6.26", "1.6.27", "1.6.33", "1.6.34",
    "1.6.35", "1.6.49", "1.6.58",
  ]) assert.ok(versions.includes(version), `Published history lost ${version}`);
  assert.doesNotMatch(history, /### (Verification|Проверка)|acceptance report/i);
  const privateAttachmentName = new RegExp(["codex", "clipboard"].join("-"), "i");
  assert.doesNotMatch(history, privateAttachmentName);
});

test("public source excludes internal CHR verification receipts", async () => {
  const exporter = await readFile(new URL("../scripts/export-public-source.ps1", import.meta.url), "utf8");
  const verifier = await readFile(new URL("../scripts/verify-public-tree.sh", import.meta.url), "utf8");
  for (const file of [
    "docs/RC3-CHR-VERIFICATION.md", "docs/RC4-CHR-VERIFICATION.md",
    "docs/LARGE-POOL-VERIFICATION.md", "docs/URLTEST-CLEANUP-VERIFICATION.md",
    "docs/URLTEST-LATENCY-VERIFICATION.md", "docs/URLTEST-SIMPLIFICATION-VERIFICATION.md",
    "docs/URLTEST-LOAD-RESEARCH.md", "docs/URLTEST-TRAFFIC-ACCOUNTING.md",
    "docs/GEOIP-BINARY-EXPERIMENT.md", "docs/XRAY-PAYLOAD-SNAPSHOT.md",
    "tools/geoipbench/run-chr.sh",
    "internal/appliance/image_artifact_test.go",
    "internal/routeros/image_transfer_chr_test.go", "internal/routeros/logging_native_test.go",
  ]) {
    assert.ok(exporter.includes("'" + file + "'"), file);
    assert.ok(verifier.includes(file), file);
  }
});

test("public security documentation excludes private acceptance reports", async () => {
  const source = await readFile(new URL("../docs/SECURITY.md", import.meta.url), "utf8");
  const verifier = await readFile(new URL("../scripts/verify-public-tree.sh", import.meta.url), "utf8");
  assert.doesNotMatch(source, /внутренних отч[её]тах при[её]мки|фактическая при[её]мка|Windows \/ Node [0-9]/);
  assert.ok(verifier.includes('"$revision" -- docs'));
  assert.ok(verifier.includes("private acceptance report exists in public documentation history"));
});

test("operational documentation contains procedures rather than internal receipts", async () => {
  const receipt = /На CHR .* составил|При первоначальной проверке|Chrome \d+\/\d+ px|\d{4}-\d{2}-\d{2} реальные ответы|конкретного failover на CHR|ранее наблюдавшегося/;
  for (const name of ["OPERATIONS", "TROUBLESHOOTING", "cdn-origin-feeds", "shared-tcp-ingress"]) {
    const source = await readFile(new URL(`../docs/${name}.md`, import.meta.url), "utf8");
    assert.doesNotMatch(source, receipt, name);
  }
  const verifier = await readFile(new URL("../scripts/verify-public-tree.sh", import.meta.url), "utf8");
  assert.ok(verifier.includes('"$private_report_pattern" -- docs'));
  assert.ok(verifier.includes("internal verification receipt exists in current public documentation"));
});
