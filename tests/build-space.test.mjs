import assert from "node:assert/strict";
import test from "node:test";
import { checkedBuild, parseDf, requireBuildSpace } from "../scripts/check-build-space.mjs";

const GiB = 1024n ** 3n;
const df = "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/test 64000000 10000000 52428800 16% /\n";

test("build reserve checks every filesystem and accepts the boundary", () => {
  requireBuildSpace([{ name: "host", available: 8n * GiB }, { name: "guest", available: 11n * GiB }]);
  assert.throws(() => requireBuildSpace([{ name: "host", available: 11n * GiB }, { name: "guest", available: 8n * GiB - 1n }]), /guest/);
  assert.throws(() => requireBuildSpace([]), /No build filesystems/);
  for (const minimum of [0, -1, 1.5, NaN, 1025]) assert.throws(() => requireBuildSpace([{ name: "host", available: 50n * GiB }], minimum));
});

test("df parsing uses available rather than total or used space", () => {
  assert.equal(parseDf(df)[0].available, 50n * GiB);
  for (const malformed of ["", "header\ninvalid", df.replace("52428800", "unknown")]) assert.throws(() => parseDf(malformed));
});

test("insufficient host space prevents the build command", () => {
  let spawned = false;
  assert.throws(() => checkedBuild(["--", "go", "build"], {
    statfs: () => ({ bavail: 1n, bsize: GiB }),
    spawn: () => { spawned = true; }, report: () => {},
  }), /Insufficient/);
  assert.equal(spawned, false);
});

test("WSL check failure and low guest space prevent the build command", () => {
  for (const response of [{ status: 1 }, { status: 0, stdout: df.replace("52428800", "1024") }, { error: new Error("timeout") }]) {
    const commands = [];
    assert.throws(() => checkedBuild(["--wsl", "test-distro", "--", "go", "build"], {
      statfs: () => ({ bavail: 50n, bsize: GiB }),
      spawn: (command) => { commands.push(command); return response; }, report: () => {},
    }));
    assert.deepEqual(commands, ["wsl.exe"]);
  }
});

test("checked build preserves command arguments and exit status without a shell", () => {
  const commands = [];
  const status = checkedBuild(["--wsl", "test-distro", "--", "go", "test", "./internal/agent"], {
    statfs: () => ({ bavail: 50n, bsize: GiB }), report: () => {},
    spawn: (command, args, options) => {
      commands.push({ command, args, options });
      return command === "wsl.exe" ? { status: 0, stdout: df } : { status: 3 };
    },
  });
  assert.equal(status, 3);
  assert.equal(commands[0].options.timeout, 30000);
  assert.equal(commands[0].args[commands[0].args.indexOf("--cd") + 1], "/");
  assert.equal(commands[0].options.cwd, process.platform === "win32" ? process.env.SystemRoot : undefined);
  assert.deepEqual(commands[1], { command: "go", args: ["test", "./internal/agent"], options: { stdio: "inherit" } });
});
