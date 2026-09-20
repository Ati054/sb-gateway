import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const projectRoot = new URL("../", import.meta.url);

test("declares AGPL-3.0-or-later across repository metadata", async () => {
  const [license, reuseLicense, dep5, packageJson, packageLock] =
    await Promise.all([
      readFile(new URL("LICENSE", projectRoot), "utf8"),
      readFile(
        new URL("LICENSES/AGPL-3.0-or-later.txt", projectRoot),
        "utf8",
      ),
      readFile(new URL(".reuse/dep5", projectRoot), "utf8"),
      readFile(new URL("package.json", projectRoot), "utf8"),
      readFile(new URL("package-lock.json", projectRoot), "utf8"),
    ]);

  assert.match(license, /GNU AFFERO GENERAL PUBLIC LICENSE/);
  assert.match(license, /Version 3, 19 November 2007/);
  assert.equal(reuseLicense, license);
  assert.match(dep5, /Files: \*/);
  assert.match(dep5, /Copyright: 2026 Ati054 <ati054@tutamail\.com>/);
  assert.match(dep5, /License: AGPL-3\.0-or-later/);
  assert.equal(JSON.parse(packageJson).license, "AGPL-3.0-or-later");
  assert.equal(
    JSON.parse(packageJson).author,
    "Ati054 <ati054@tutamail.com> (https://github.com/Ati054)",
  );
  assert.equal(
    JSON.parse(packageLock).packages[""].license,
    "AGPL-3.0-or-later",
  );
  assert.equal(
    JSON.parse(packageLock).packages[""].author,
    "Ati054 <ati054@tutamail.com> (https://github.com/Ati054)",
  );
});
