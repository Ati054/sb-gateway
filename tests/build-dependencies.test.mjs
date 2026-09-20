import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";
import { hardenImageSize, patchedSource, sha256, targets } from "../build/harden-image-size.mjs";

// A subprocess timeout makes a regression fail instead of hanging the test runner.
function inspect(target, bytes) {
  const result = spawnSync(process.execPath, ["--input-type=module", "-e", `
    const module = await import(${JSON.stringify(pathToFileURL(resolve(target.file)).href)});
    const size = module.imageSize ?? module.default.imageSize ?? module.default;
    try { console.log(JSON.stringify({ size: size(Buffer.from(${JSON.stringify(bytes.toString("base64"))}, "base64")) })); }
    catch (error) { console.log(JSON.stringify({ error: error.message })); }
  `], { encoding: "utf8", timeout: 5000 });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

function box(name, body = Buffer.alloc(0), declaredSize = 8 + body.length) {
  const header = Buffer.alloc(8);
  header.writeUInt32BE(declaredSize, 0);
  header.write(name, 4, "ascii");
  return Buffer.concat([header, body]);
}

function icns(length = 8, fileLength = 16) {
  const image = Buffer.from("69636e73000000106963703400000008", "hex");
  image.writeUInt32BE(fileLength, 4);
  image.writeUInt32BE(length, 12);
  return image;
}

function heif(size = 20) {
  const dimensions = Buffer.alloc(12);
  dimensions.writeUInt32BE(32, 4);
  dimensions.writeUInt32BE(24, 8);
  return Buffer.concat([
    box("ftyp", Buffer.from("heic0000")),
    box("meta", Buffer.concat([Buffer.alloc(4), box("iprp", box("ipco", box("ispe", dimensions, size)))])),
  ]);
}

function jxl(size) {
  return Buffer.concat([
    box("JXL ", Buffer.from("0d0a870a", "hex")),
    box("ftyp", Buffer.from("jxl 0000")),
    box("jxlp", Buffer.alloc(4), size),
  ]);
}

test("hardening is idempotent and rejects unknown bundled source", () => {
  hardenImageSize();
  hardenImageSize();
  for (const target of targets) {
    const source = readFileSync(target.file, "utf8");
    assert.equal(sha256(source), target.patched);
    assert.throws(() => patchedSource(target, source + "changed"), /Unexpected/);
  }
});

for (const target of targets) {
  test(`${target.package}: ICNS zero, short, overflowing and truncated chunks cannot hang`, () => {
    hardenImageSize();
    for (const bytes of [icns(0), icns(1), icns(7), icns(100), icns(8, 100), icns(8, 12), icns().subarray(0, 12)]) {
      assert.match(inspect(target, bytes).error, /Invalid ICNS/);
    }
    assert.equal(inspect(target, icns()).size.width, 16);
  });

  test(`${target.package}: JXL/HEIF boxes always advance, including ISO box size zero (to EOF)`, () => {
    hardenImageSize();
    for (const size of [0, 1, 7, 0xffffffff]) {
      const result = inspect(target, jxl(size));
      assert.ok(result.error || result.size);
    }
    for (const size of [1, 7, 0xffffffff]) assert.ok(inspect(target, heif(size)).error);
    for (const size of [0, 20]) {
      const result = inspect(target, heif(size));
      assert.equal(result.size.width, 32);
      assert.equal(result.size.height, 24);
    }
  });

  test(`${target.package}: ordinary PNG/GIF/JPEG/SVG dimensions are preserved`, () => {
    hardenImageSize();
    const images = [
      Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jB9sAAAAASUVORK5CYII=", "base64"),
      Buffer.from("47494638396101000100800000000000ffffff21f90401000000002c00000000010001000002024401003b", "hex"),
      Buffer.from("ffd8ffe000104a46494600010100000100010000ffc00011080001000103011100021100031100ffd9", "hex"),
      Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"></svg>'),
    ];
    for (const image of images) {
      const result = inspect(target, image);
      assert.equal(result.size?.width, 1, JSON.stringify(result));
      assert.equal(result.size?.height, 1);
    }
  });
}

test("normal npm entry points enforce hardening even after npm ci --ignore-scripts", () => {
  const { scripts } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  for (const name of ["postinstall", "predev", "prebuild", "prebuild:static", "prestart"]) {
    assert.equal(scripts[name], "node build/harden-image-size.mjs");
  }
  assert.equal(scripts["audit:dependencies"], "npm audit --audit-level=low && npm run test:dependencies");
  assert.match(scripts.test, /--test tests\/\*\.test\.mjs$/);
  const docker = readFileSync(new URL("../Dockerfile", import.meta.url), "utf8");
  assert.ok(docker.includes("COPY build ./build"));
  assert.ok(docker.includes("npm run build:static"));
  assert.ok(docker.indexOf("COPY build ./build") < docker.indexOf("npm run build:static"));
});
