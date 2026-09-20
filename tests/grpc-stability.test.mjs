import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const page = await readFile(new URL("../app/page.tsx", import.meta.url), "utf8");
const defaultConfig = JSON.parse(
  await readFile(new URL("../internal/controlplane/default-config.json", import.meta.url), "utf8"),
);

test("new direct gRPC transports keep an idle HTTP/2 health check", () => {
  for (const kind of ["reality-grpc", "grpc-tls"]) {
    const transport = defaultConfig.transports.find((item) => item.kind === kind);
    assert.ok(transport);
    assert.equal(transport.grpc_idle_timeout, 60);
    assert.equal(transport.grpc_health_check_timeout, 20);
    assert.equal(transport.grpc_permit_without_stream, true);
  }
});

test("the direct gRPC form and reset use the direct-only defaults", () => {
  assert.match(page, /const directGRPCKind = \["reality-grpc", "grpc-tls"\]\.includes\(transportKind\)/);
  assert.match(page, /const grpcIdleTimeoutDefault = directGRPCKind \? "60" : "0"/);
  assert.match(
    page,
    /field\.name === "grpc_permit_without_stream"\) return \{ \.\.\.field, value: true \}/,
  );
  assert.match(
    page,
    /fields: \[\.\.\.REALITY_RECOMMENDATION_FIELDS, \.\.\.DIRECT_GRPC_RECOMMENDATION_FIELDS\]/,
  );
  assert.match(
    page,
    /directGRPCKind[\s\S]*?0 — автоматический размер\. Большее окно может повысить скорость на канале с высокой задержкой, но требует больше памяти\.[\s\S]*?: tr\("0 — авто\. Для Cloudflare обычно проверяют 65536 и выше\."\)/,
  );
});

test("the transport dialog uses the saved kind instead of treating an arbitrary id as a kind", () => {
  const dialogStart = page.indexOf("function ConnectionDialog(");
  const dialogEnd = page.indexOf("function SetupWizard(", dialogStart);
  const dialog = page.slice(dialogStart, dialogEnd);

  assert.match(
    dialog,
    /const savedTransportKind = asText\(existingTransport\.kind, ""\)\.trim\(\)/,
  );
  assert.match(dialog, /const transportKind = savedTransportKind \|\|/);
  assert.match(
    dialog,
    /tr\("Настроить \{value1\}", \{ value1: transportKindLabel\(transportKind\) \}\)/,
  );
  assert.match(page, /"grpc-tls": "VLESS \+ gRPC \+ TLS Pin"/);
  assert.match(
    dialog,
    /\["grpc", "grpc-tls"\]\.includes\(transportKind\)[\s\S]*?Дополнительно[\s\S]*?gRPC/,
  );
  const placeholderStart = dialog.indexOf("const hostnamePlaceholder");
  const placeholderEnd = dialog.indexOf("const connectionAddress", placeholderStart);
  const placeholder = dialog.slice(placeholderStart, placeholderEnd);
  assert.match(placeholder, /\["reality", "reality-grpc", "grpc-tls", "xhttp-reality", "hysteria2"\]/);
  assert.doesNotMatch(placeholder, /grpc-tls-pin|grpc-reality|direct-reality/);
});
