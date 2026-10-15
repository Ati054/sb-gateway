import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("both introductions put requirements and a synthetic panel preview before technical details", async () => {
  for (const [name, requirements, technical] of [
    ["README.md", "## What You Need", "## Technical Overview"],
    ["README-RU.md", "## Что Понадобится", "## Техническое Устройство"],
  ]) {
    const body = await readFile(new URL(`../${name}`, import.meta.url), "utf8");
    assert.ok(body.indexOf(requirements) > 0);
    assert.ok(body.indexOf(technical) > body.indexOf(requirements));
    assert.ok(body.indexOf("docs/images/panel-routing.png") < body.indexOf(technical));
    assert.doesNotMatch(body.slice(0, body.indexOf(requirements)), /TPROXY|REALITY|XHTTP|peer/);
    assert.match(body, /releases\/latest/);
    assert.doesNotMatch(body, /sb-gateway-1\.6\.45-routeros-bundle/);
  }
  const image = await readFile(new URL("../docs/images/panel-routing.png", import.meta.url));
  assert.equal(image.subarray(1, 4).toString(), "PNG");
  assert.ok(image.readUInt32BE(16) >= 1000);
  assert.ok(image.readUInt32BE(20) >= 600);
});
