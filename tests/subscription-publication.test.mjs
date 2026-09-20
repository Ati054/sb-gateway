import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { disableSubscriptionPublication } from "../app/subscription-publication.ts";
import { normalizeLocalizedSource } from "./source-localization.mjs";

test("disabling publication preserves the complete saved endpoint configuration", () => {
  const source = {
    system: { deployment_ready: true },
    ingress: {
      subscription_endpoint_enabled: true,
      subscription_hostname: "edge.example.test",
      subscription_origin_server_name: "origin.example.test",
      subscription_tls_profile_id: "origin-tls",
      subscription_endpoint_mode: "separate",
    },
  };
  assert.deepEqual(disableSubscriptionPublication(source), {
    system: { deployment_ready: true },
    ingress: {
      subscription_endpoint_enabled: false,
      subscription_hostname: "edge.example.test",
      subscription_origin_server_name: "origin.example.test",
      subscription_tls_profile_id: "origin-tls",
      subscription_endpoint_mode: "separate",
    },
  });
  assert.equal(source.system.deployment_ready, true);
  assert.equal(source.ingress.subscription_endpoint_enabled, true);
});

test("Connections keeps the publication toggle outside disabled endpoint fields", async () => {
  const page = normalizeLocalizedSource(await readFile(new URL("../app/page.tsx", import.meta.url), "utf8"));
  assert.match(page, /disableSubscriptionPublication\(config\)/);
  assert.match(page, /label="Публикация подписки"/);
  assert.match(page, /<fieldset className="subscription-publication-fields" disabled=\{!subscriptionEndpointEnabled\}>/);
  assert.ok(page.indexOf('label="Публикация подписки"') < page.indexOf('className="subscription-publication-fields"'));
  assert.match(page, /subscription_endpoint_enabled:\s*true/);
});

test("client-only defaults do not require public TLS", async () => {
  const page = normalizeLocalizedSource(await readFile(new URL("../app/page.tsx", import.meta.url), "utf8"));
  assert.match(page, /return required\.every\(\(transport\) =>/);
  assert.match(page, /subscription_endpoint_enabled:\s*Boolean\(subscriptionHost\)/);
  assert.match(page, /if \(step === 2 && subscriptionHost && !subscriptionHost\.includes\("\."\)\)/);
  assert.match(page, /transports:\s*currentTransports\.map\(\(transport\) => \(\{[\s\S]*enabled:\s*false,[\s\S]*cdn_deployments:[\s\S]*enabled:\s*false/);
  assert.match(page, /tls_profiles:\s*asObjectList\(config\.tls_profiles\)\.filter\([\s\S]*profile\.certificate_secret_ref[\s\S]*profile\.private_key_secret_ref/);
});

test("disabling a CDN transport also disables its deployments and required fields", async () => {
  const page = normalizeLocalizedSource(await readFile(new URL("../app/page.tsx", import.meta.url), "utf8"));
  assert.match(page, /required=\{transportEnabled && deployment\.enabled !== false\}/);
  assert.match(page, /if \(!enabled && cdnTransportKind\)[\s\S]*current\.map\(\(deployment\) => \(\{ \.\.\.deployment, enabled: false \}\)\)/);
});

test("Connections persists the Happ Provider ID used for managed mobile routes", async () => {
  const page = normalizeLocalizedSource(await readFile(new URL("../app/page.tsx", import.meta.url), "utf8"));
  assert.match(page, /Happ Provider ID/);
  assert.match(page, /happ_provider_id:\s*happProviderId\.trim\(\)/);
  assert.match(page, /configuredHappProviderId/);
  assert.match(page, /Include all networks вручную/);
});

test("Remote users keep their Happ tunnel preferences separate", async () => {
  const page = normalizeLocalizedSource(await readFile(new URL("../app/page.tsx", import.meta.url), "utf8"));
  assert.match(page, /Happ на iOS · системный туннель/);
  assert.match(page, /Доступно только после настройки Happ Provider ID/);
  assert.match(page, /happ_include_all_networks:\s*happIncludeAllNetworks/);
  assert.match(page, /happ_exclude_local_networks:\s*happExcludeLocalNetworks/);
  assert.match(page, /happ_exclude_apns:\s*happExcludeAPNs/);
  assert.match(page, /последняя обновившаяся подписка имеет приоритет/);
});

test("Connections keeps direct and dedicated CDN hostnames separate", async () => {
  const page = normalizeLocalizedSource(await readFile(new URL("../app/page.tsx", import.meta.url), "utf8"));
  assert.match(page, /subscription_cdn_hostname/);
  assert.match(page, /configuredSubscriptionEndpointMode === "separate"[\s\S]*configuredSubscriptionOriginServerName/);
  assert.match(page, /value="subscription-cdn"/);
  assert.match(page, /subscriptionEndpointMode === "separate"[\s\S]*nextSubscriptionCdnHostname[\s\S]*nextSubscriptionDirectHostname/);
});

test("Connections keeps CDN edge and MikroTik origin ports separate", async () => {
  const page = await readFile(new URL("../app/page.tsx", import.meta.url), "utf8");
  assert.match(page, /subscription_public_port:\s*subscriptionHasEditablePublicCdnPort/);
  assert.match(page, /subscription_listen_port:\s*subscriptionOriginPort/);
  assert.match(page, /Публичный HTTPS-порт/);
  assert.match(page, /TCP-порт origin на MikroTik/);
  assert.match(page, /subscriptionPublicPort[\s\S]*subscriptionOriginPort/);
});
