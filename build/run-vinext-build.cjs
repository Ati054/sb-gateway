const path = require("path");
const { spawnSync } = require("child_process");

const executable =
  process.platform === "win32"
    ? path.join(process.cwd(), "node_modules", ".bin", "vinext.cmd")
    : path.join(process.cwd(), "node_modules", ".bin", "vinext");

const command =
  process.platform === "win32" ? process.env.ComSpec || "cmd.exe" : executable;
const args =
  process.platform === "win32"
    ? ["/d", "/c", `${executable} build`]
    : ["build"];

const result = spawnSync(command, args, {
  cwd: process.cwd(),
  env: {
    ...process.env,
    SB_BUILD_TARGET: "sites",
    WRANGLER_LOG_PATH: ".wrangler/wrangler.log",
  },
  stdio: "inherit",
});

if (result.error) {
  throw result.error;
}

process.exit(result.status ?? 1);
