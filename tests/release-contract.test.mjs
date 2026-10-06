import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

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
  for (const file of ["docs/RC3-CHR-VERIFICATION.md", "docs/RC4-CHR-VERIFICATION.md"]) {
    assert.ok(exporter.includes("'" + file + "'"), file);
    assert.ok(verifier.includes(file), file);
  }
});
