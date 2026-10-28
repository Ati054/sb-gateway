import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

test("final image includes every startup script dependency", async () => {
  const docker = await readFile("Dockerfile", "utf8");
  const runtime = docker.split(/FROM[^\n]+ AS runtime\r?\n/).at(-1);
  assert.notEqual(runtime, docker, "runtime stage not found");
  const copies = [...runtime.matchAll(/^COPY (?!.*--from=)([^\r\n]+)/gm)].map(m => m[1]).join(" ").split(/\s+/);
  for (const source of ["entrypoint.sh", "scripts/run-xray.sh"]) {
    const text = await readFile(source, "utf8");
    for (const match of text.matchAll(/\/opt\/sb-gateway\/scripts\/([a-z0-9-]+\.sh)/g)) {
      assert.ok(copies.includes(`scripts/${match[1]}`), `${source} needs an absent runtime image file: ${match[1]}`);
    }
  }
  assert.match(runtime, /test -x scripts\/validate-xray\.sh/);
  assert.match(runtime, /scripts\/validate-xray\.sh "\$validation_dir\/xray.json"/);
});

test("startup validation hides successful chatter and preserves failed diagnostics", {
  skip: process.platform === "win32" ? "POSIX shell integration runs on Linux" : false,
}, async () => {
  const root = await mkdtemp(join(tmpdir(), "sb-xray-validation-test-"));
  try {
    await mkdir(join(root, "logs"));
    await writeFile(join(root, "xray"), `#!/bin/sh
test "$1 $2 $3" = 'run -test -config' || exit 99
printf '%s\\n' 'Xray version banner' 'configuration warning' >&2
if [ "$4" = bad ]; then
  printf '%s\\n' 'Failed to start: invalid REALITY private key' >&2
  exit 23
fi
printf '%s\\n' 'Configuration OK.'
`, { mode: 0o700 });
    const run = (config) => spawnSync("/bin/sh", [resolve("scripts/validate-xray.sh"), config], {
      encoding: "utf8",
      env: { ...process.env, PATH: `${root}:${process.env.PATH}`, TMPDIR: join(root, "logs") },
    });
    const valid = run("good");
    assert.equal(valid.status, 0);
    assert.equal(valid.stdout, "");
    assert.equal(valid.stderr, "");
    assert.deepEqual(await readdir(join(root, "logs")), []);
    const failed = run("bad");
    assert.equal(failed.status, 23);
    assert.equal(failed.stdout, "");
    assert.match(failed.stderr, /configuration warning/);
    assert.match(failed.stderr, /Failed to start: invalid REALITY private key/);
    assert.deepEqual(await readdir(join(root, "logs")), []);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
