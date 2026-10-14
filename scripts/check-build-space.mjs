import { statfsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";

const GiB = 1024n ** 3n;

export function requireBuildSpace(snapshots, minimumGiB = 8) {
  if (!Number.isSafeInteger(minimumGiB) || minimumGiB < 1 || minimumGiB > 1024) {
    throw new Error("Minimum free space must be an integer from 1 to 1024 GiB");
  }
  if (!snapshots.length) throw new Error("No build filesystems checked");
  const minimum = BigInt(minimumGiB) * GiB;
  for (const { name, available } of snapshots) {
    if (typeof available !== "bigint" || available < minimum) {
      throw new Error(`Insufficient build space on ${name}; at least ${minimumGiB} GiB required`);
    }
  }
}

export function parseDf(output) {
  const lines = output.trim().split(/\r?\n/).slice(1);
  if (!lines.length) throw new Error("No WSL filesystem information returned");
  return lines.map((line) => {
    const fields = line.trim().split(/\s+/);
    if (fields.length < 6 || !/^\d+$/.test(fields[3])) {
      throw new Error("Invalid WSL filesystem information");
    }
    return { name: `WSL:${fields.slice(5).join(" ")}`, available: BigInt(fields[3]) * 1024n };
  });
}

export function checkedBuild(args, deps = { statfs: statfsSync, spawn: spawnSync, report: console.log }) {
  const separator = args.indexOf("--");
  const command = separator < 0 ? [] : args.slice(separator + 1);
  const { values } = parseArgs({ args: separator < 0 ? args : args.slice(0, separator), options: {
    path: { type: "string", multiple: true },
    wsl: { type: "string" },
    "wsl-path": { type: "string", multiple: true },
    "min-free-gib": { type: "string", default: "8" },
  } });
  const snapshots = (values.path ?? [process.cwd()]).map((path) => {
    const fs = deps.statfs(resolve(path), { bigint: true });
    return { name: resolve(path), available: fs.bavail * fs.bsize };
  });
  if (values.wsl) {
    const paths = values["wsl-path"] ?? ["/var/lib/docker", "/tmp"];
    const result = deps.spawn("wsl.exe", ["--distribution", values.wsl, "--user", "root", "--cd", "/",
      "--exec", "df", "-Pk", "--", ...paths], {
      encoding: "utf8", timeout: 30000,
      cwd: process.platform === "win32" ? process.env.SystemRoot : undefined,
    });
    if (result.error || result.status !== 0) throw new Error("Cannot verify WSL free space");
    snapshots.push(...parseDf(result.stdout));
  } else if (values["wsl-path"]) {
    throw new Error("--wsl-path requires --wsl");
  }
  requireBuildSpace(snapshots, Number(values["min-free-gib"]));
  for (const { name, available } of snapshots) deps.report(`${name}: ${(Number(available) / Number(GiB)).toFixed(1)} GiB free`);
  if (!command.length) return 0;
  const result = deps.spawn(command[0], command.slice(1), { stdio: "inherit" });
  if (result.error) throw result.error;
  return result.status ?? 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try { process.exitCode = checkedBuild(process.argv.slice(2)); }
  catch (error) { console.error(error.message); process.exitCode = 1; }
}
