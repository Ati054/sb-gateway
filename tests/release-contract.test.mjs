import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("release image declares the in-place update contract", async () => {
  const dockerfile = await readFile(new URL("../Dockerfile", import.meta.url), "utf8");
  assert.match(dockerfile, /io\.sb-gateway\.lifecycle\.version="1"/);
  assert.match(dockerfile, /io\.sb-gateway\.config\.schema="1"/);
  assert.match(dockerfile, /io\.sb-gateway\.config\.minimum-schema="1"/);
});
