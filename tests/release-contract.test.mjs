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

test("public changelog stops at either stable or numbered RC headings", async () => {
  const source = await readFile(new URL("../scripts/export-public-source.ps1", import.meta.url), "utf8");
  const match = source.match(/\$changelogLines\[\$index\] -match '([^']+)'/);
  assert.ok(match, "Missing changelog boundary guard");
  const guard = new RegExp(match[1]);
  for (const heading of ["## 1.6.43", "## 1.6.44-rc.2", "## 1.6.44-rc.12"]) assert.ok(guard.test(heading), heading);
  for (const heading of ["### Changes", "## 1.6.44-rc.0", "## 1.6.44-rc"]) assert.ok(!guard.test(heading), heading);
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
