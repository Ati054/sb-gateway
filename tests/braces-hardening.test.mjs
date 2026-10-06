import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";
import { bracesTargets, hardenBraces, patchedBracesSource } from "../build/harden-braces.mjs";
import { sha256 } from "../build/harden-image-size.mjs";

test("braces hardening is idempotent and rejects unreviewed sources", () => {
  hardenBraces(process.cwd());
  hardenBraces(process.cwd());
  for (const target of bracesTargets) {
    const source = readFileSync(`node_modules/braces/lib/${target.file}`, "utf8");
    assert.equal(sha256(source), target.patched);
    assert.throws(() => patchedBracesSource(target, source + "changed"), /Unexpected/);
  }
});

test("deep braces, parentheses and public AST walkers fail before stack exhaustion", () => {
  hardenBraces(process.cwd());
  const result = spawnSync(process.execPath, ["--input-type=commonjs", "-e", `
    const assert = require("node:assert/strict");
    const braces = require("braces");
    for (const method of ["parse", "compile", "expand", "stringify"]) {
      for (const [open, close] of [["{", "}"], ["(", ")"]]) {
        assert.throws(() => braces[method](open.repeat(4000) + "a,b" + close.repeat(4000)),
          error => error instanceof SyntaxError && /safe depth/.test(error.message));
      }
    }
    let ast = { type: "root", nodes: [] };
    for (let i = 0; i < 10000; i++) ast = { type: "root", nodes: [ast] };
    for (const method of ["compile", "expand", "stringify"]) {
      assert.throws(() => braces[method](ast),
        error => error instanceof SyntaxError && /safe depth/.test(error.message));
    }
    assert.deepEqual(braces.expand("src/{app,tests}/*.{ts,tsx}"),
      ["src/app/*.ts", "src/app/*.tsx", "src/tests/*.ts", "src/tests/*.tsx"]);
    assert.deepEqual(braces.expand("{01..03}"), ["01", "02", "03"]);
    assert.equal(braces.stringify(braces.parse("foo/{bar,baz}")), "foo/{bar,baz}");
    assert.equal(require("micromatch").isMatch("app/page.tsx", "**/*.{ts,tsx}"), true);
  `], { encoding: "utf8", timeout: 5000 });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
});
