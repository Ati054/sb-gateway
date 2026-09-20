import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const page = await readFile(new URL("../app/page.tsx", import.meta.url), "utf8");
const healthcheck = await readFile(new URL("../scripts/healthcheck.sh", import.meta.url), "utf8");

test("recommended XHTTP XMUX settings bound mobile connection growth", () => {
  assert.match(
    page,
    /name: "xmux_max_connections", label: "XMUX maxConnections", value: "3"/,
  );
  assert.match(
    page,
    /name: "xmux_max_concurrency", label: "XMUX maxConcurrency", value: "0"/,
  );
  assert.match(
    page,
    /name="xmux_max_connections"[^>]+defaultValue=\{asText\(existingTransport\.xmux_max_connections, "3"\)\}/,
  );
  assert.match(
    page,
    /name="xmux_max_concurrency"[^>]+defaultValue=\{asText\(existingTransport\.xmux_max_concurrency, "0"\)\}/,
  );
});

test("OCI health probes run concurrently inside the RouterOS deadline", () => {
  assert.equal((healthcheck.match(/--max-time 7/g) ?? []).length, 2);
  assert.match(healthcheck, /api_probe_pid=\$!/);
  assert.match(healthcheck, /https_probe_pid=\$!/);
  assert.match(healthcheck, /wait "\$api_probe_pid" \|\| probe_status=1/);
  assert.match(healthcheck, /wait "\$https_probe_pid" \|\| probe_status=1/);
});
