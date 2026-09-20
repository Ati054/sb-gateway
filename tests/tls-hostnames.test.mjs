import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import ts from "typescript";
import {
  canonicalConcreteHostname,
  certificateCoversHostname,
  cdnDeploymentAfterTLSProfileChange,
  cdnDeploymentForTLSInitialization,
  hostnameAfterTLSProfileChange,
  hostnameForTLSProfileInitialization,
  subscriptionEndpointValueAfterConfigRefresh,
  subscriptionEndpointUsesTLSHostname,
  tlsConcreteHostnames,
  tlsProfileIdForHostname,
} from "../app/tls-hostnames.ts";

const sole = { certificate_metadata: { dns_names: ["Origin.Example.test."] } };
const multiple = { certificate_metadata: { dns_names: ["first.example.test", "second.example.test"] } };
const wildcard = { certificate_metadata: { dns_names: ["*.example.test"] } };

test("TLS hostname candidates contain only canonical concrete DNS SANs", () => {
  assert.equal(canonicalConcreteHostname(" Origin.Example.test. "), "origin.example.test");
  assert.equal(canonicalConcreteHostname("*.example.test"), "");
  assert.equal(canonicalConcreteHostname("1.2.3.4"), "");
  assert.deepEqual(
    tlsConcreteHostnames({ certificate_metadata: { dns_names: ["one.example.test.", "ONE.example.test", "*.example.test", "1.2.3.4"] } }),
    ["one.example.test"],
  );
});

test("API cover is offered only for a hostname covered by the selected certificate", () => {
  assert.equal(certificateCoversHostname(sole, "origin.example.test"), true);
  assert.equal(certificateCoversHostname(wildcard, "api.example.test"), true);
  assert.equal(certificateCoversHostname(wildcard, "nested.api.example.test"), false);
  assert.equal(certificateCoversHostname(sole, "www.microsoft.com"), false);
});

test("typed SNI selects one provably matching enabled TLS profile", () => {
  const profiles = [
    { id: "exact", enabled: true, certificate_metadata: { dns_names: ["api.example.test"] } },
    { id: "wildcard", enabled: true, certificate_metadata: { dns_names: ["*.example.test"] } },
    { id: "local-ca", enabled: true, local_ca_server_name: "private.example.test" },
    { id: "disabled", enabled: false, certificate_metadata: { dns_names: ["off.example.invalid"] } },
  ];
  assert.equal(tlsProfileIdForHostname(profiles, "API.EXAMPLE.TEST.", ""), "exact");
  assert.equal(tlsProfileIdForHostname(profiles, "edge.example.test", ""), "wildcard");
  assert.equal(tlsProfileIdForHostname(profiles, "private.example.test", ""), "local-ca");
  assert.equal(tlsProfileIdForHostname(profiles, "off.example.invalid", "kept"), "kept");
  assert.equal(tlsProfileIdForHostname(profiles, "not a hostname", "kept"), "kept");
});

test("ambiguous SNI matches preserve the current profile instead of guessing", () => {
  const profiles = [
    { id: "first", certificate_metadata: { dns_names: ["same.example.test"] } },
    { id: "second", certificate_metadata: { dns_names: ["same.example.test"] } },
  ];
  assert.equal(tlsProfileIdForHostname(profiles, "same.example.test", "second"), "second");
  assert.equal(tlsProfileIdForHostname(profiles, "same.example.test", ""), "");
});

test("explicit TLS profile changes synchronize only a provable origin hostname", () => {
  assert.equal(hostnameAfterTLSProfileChange(sole, "manual.example.test"), "origin.example.test");
  assert.equal(hostnameAfterTLSProfileChange(multiple, "SECOND.example.test."), "second.example.test");
  assert.equal(hostnameAfterTLSProfileChange(multiple, "manual.example.test"), "");
  assert.equal(hostnameAfterTLSProfileChange(wildcard, "api.example.test"), "api.example.test");
  assert.equal(hostnameAfterTLSProfileChange(wildcard, "other.example.net"), "");
  assert.equal(hostnameAfterTLSProfileChange(wildcard, "nested.api.example.test"), "");
  assert.equal(hostnameAfterTLSProfileChange(wildcard, "example.test"), "");
  assert.equal(hostnameAfterTLSProfileChange({}, "manual.example.test"), "manual.example.test");
});

test("initialization fills only an eligible empty hostname", () => {
  assert.equal(hostnameForTLSProfileInitialization(sole, "status.example.test", true), "origin.example.test");
  assert.equal(hostnameForTLSProfileInitialization(sole, "manual.example.test", false), "manual.example.test");
  assert.equal(hostnameForTLSProfileInitialization(multiple, "status.example.test", true), "status.example.test");
});

test("only direct subscription endpoints share their TLS hostname", () => {
  assert.equal(subscriptionEndpointUsesTLSHostname("direct"), true);
  assert.equal(subscriptionEndpointUsesTLSHostname("direct-and-cdn"), true);
  assert.equal(subscriptionEndpointUsesTLSHostname("separate"), false);
  assert.equal(subscriptionEndpointUsesTLSHostname("reuse-cdn"), false);
});

test("config refresh keeps an open subscription endpoint draft", () => {
  const typedHostname = "typed.example.test";
  const chosenTLS = "tls-typed";
  assert.equal(subscriptionEndpointValueAfterConfigRefresh(typedHostname, "origin.example.test", true), typedHostname);
  assert.equal(subscriptionEndpointValueAfterConfigRefresh(chosenTLS, "tls-refreshed", true), chosenTLS);
  assert.equal(subscriptionEndpointValueAfterConfigRefresh(typedHostname, "origin.example.test", false), "origin.example.test");
});

test("actual Connections refresh effect keeps an open typed hostname and TLS choice", async () => {
  const page = await readFile(new URL("../app/page.tsx", import.meta.url), "utf8");
  const parsed = ts.createSourceFile("page.tsx", page, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  let refreshEffect;
  function visit(node) {
    if (
      ts.isCallExpression(node) &&
      node.expression.getText(parsed) === "useEffect" &&
      node.arguments[0]?.getText(parsed).includes("setSubscriptionOriginPort")
    ) refreshEffect = node.arguments[0];
    ts.forEachChild(node, visit);
  }
  visit(parsed);
  assert.ok(refreshEffect, "subscription endpoint refresh effect must exist");
  const compiled = ts.transpileModule(
    `function runRefresh(props) {
      const { configuredSubscriptionOriginPort, configuredSubscriptionPublicPort, initialSubscriptionHostname, configuredSubscriptionCdnHostname, initialSubscriptionOriginServerName, configuredSubscriptionTlsProfileId, configuredSubscriptionCdnProvider, configuredSubscriptionEndpointMode, configuredSubscriptionEndpointEnabled, configuredSubscriptionPrimaryEndpoint, configuredSubscriptionTransportId, configuredSubscriptionDeploymentId, configuredSubscriptionDisplayName, configuredHappProviderId, configuredSubscriptionOriginProtectionMode, subscriptionEndpointDialogOpen, setSubscriptionOriginPort, setSubscriptionPublicPort, setSubscriptionHostname, setSubscriptionCdnHostname, setSubscriptionOriginServerName, setSubscriptionTlsProfileId, setSubscriptionCdnProvider, setSubscriptionEndpointMode, setSubscriptionEndpointEnabled, setSubscriptionPrimaryEndpoint, setSubscriptionDeploymentSelection, setSubscriptionDisplayName, setHappProviderId, setSubscriptionOriginProtectionMode, setSubscriptionOriginHeaderValue } = props;
      return (${refreshEffect.getText(parsed)})();
    }`,
    { compilerOptions: { target: ts.ScriptTarget.ES2022 } },
  ).outputText;
  const runRefresh = new Function(
    "window",
    "subscriptionEndpointValueAfterConfigRefresh",
    `${compiled}; return runRefresh;`,
  )(
    { setTimeout: (callback) => { callback(); return 1; }, clearTimeout: () => {} },
    subscriptionEndpointValueAfterConfigRefresh,
  );
  const run = (open) => {
    const current = {
      port: 8443, publicPort: 9443, hostname: "typed.example.test", cdnHostname: "typed-cdn.example.test", origin: "typed-origin.example.test", tls: "tls-typed", cdn: "gcore",
      mode: "direct", primary: "direct", deployment: "typed::deployment",
      display: "Typed", happ: "typed-provider", publication: false, protection: "secret-header", header: "typed-secret",
    };
    const setter = (key) => (next) => { current[key] = typeof next === "function" ? next(current[key]) : next; };
    runRefresh({
      configuredSubscriptionOriginPort: 18443, configuredSubscriptionPublicPort: 443, initialSubscriptionHostname: "refreshed.example.test", configuredSubscriptionCdnHostname: "refreshed-cdn.example.test", initialSubscriptionOriginServerName: "refreshed-origin.example.test",
      configuredSubscriptionTlsProfileId: "tls-refreshed", configuredSubscriptionCdnProvider: "cloudflare",
      configuredSubscriptionEndpointMode: "separate", configuredSubscriptionEndpointEnabled: true, configuredSubscriptionPrimaryEndpoint: "cdn",
      configuredSubscriptionTransportId: "refreshed", configuredSubscriptionDeploymentId: "edge",
      configuredSubscriptionDisplayName: "Refreshed", configuredHappProviderId: "refreshed-provider", configuredSubscriptionOriginProtectionMode: "auto-cidr",
      subscriptionEndpointDialogOpen: open,
      setSubscriptionOriginPort: setter("port"), setSubscriptionPublicPort: setter("publicPort"), setSubscriptionHostname: setter("hostname"), setSubscriptionCdnHostname: setter("cdnHostname"), setSubscriptionOriginServerName: setter("origin"),
      setSubscriptionTlsProfileId: setter("tls"), setSubscriptionCdnProvider: setter("cdn"),
      setSubscriptionEndpointMode: setter("mode"), setSubscriptionEndpointEnabled: setter("publication"), setSubscriptionPrimaryEndpoint: setter("primary"),
      setSubscriptionDeploymentSelection: setter("deployment"), setSubscriptionDisplayName: setter("display"),
      setHappProviderId: setter("happ"),
      setSubscriptionOriginProtectionMode: setter("protection"), setSubscriptionOriginHeaderValue: setter("header"),
    });
    return current;
  };
  assert.deepEqual(run(true), {
    port: 8443, publicPort: 9443, hostname: "typed.example.test", cdnHostname: "typed-cdn.example.test", origin: "typed-origin.example.test", tls: "tls-typed", cdn: "gcore",
    mode: "direct", primary: "direct", deployment: "typed::deployment",
    display: "Typed", happ: "typed-provider", publication: false, protection: "secret-header", header: "typed-secret",
  });
  assert.deepEqual(run(false), {
    port: 18443, publicPort: 443, hostname: "refreshed.example.test", cdnHostname: "refreshed-cdn.example.test", origin: "refreshed-origin.example.test", tls: "tls-refreshed", cdn: "cloudflare",
    mode: "separate", primary: "cdn", deployment: "refreshed::edge",
    display: "Refreshed", happ: "refreshed-provider", publication: true, protection: "auto-cidr", header: "",
  });
});

test("CDN TLS changes never replace the public edge hostname", () => {
  const deployment = {
    hostname: "edge.cdn.example.test",
    origin_server_name: "manual-origin.example.test",
    tls_profile_id: "old",
  };
  const next = cdnDeploymentAfterTLSProfileChange(deployment, "new", sole);
  assert.equal(next.hostname, "edge.cdn.example.test");
  assert.equal(next.tls_profile_id, "new");
  assert.equal(next.origin_server_name, "origin.example.test");
  assert.equal(
    cdnDeploymentForTLSInitialization(
      { hostname: "edge.cdn.example.test", origin_server_name: "saved.example.test" },
      sole,
    ).origin_server_name,
    "saved.example.test",
  );
  assert.equal(
    cdnDeploymentForTLSInitialization(
      { hostname: "edge.cdn.example.test", origin_server_name: "" },
      sole,
    ).origin_server_name,
    "origin.example.test",
  );
});

test("subscription edge and origin fields use separate native datalists", async () => {
  const page = await readFile(new URL("../app/page.tsx", import.meta.url), "utf8");
  const css = await readFile(new URL("../app/globals.css", import.meta.url), "utf8");
  assert.match(page, /list=\{subscriptionHostnameDatalistId\}/);
  assert.match(page, /id=\{subscriptionHostnameDatalistId\}/);
  assert.match(page, /list=\{subscriptionOriginDatalistId\}/);
  assert.match(page, /id=\{subscriptionOriginDatalistId\}/);
  assert.match(page, /list=\{originHostnameDatalistId\}/);
  assert.match(page, /id=\{originHostnameDatalistId\}/);
  assert.match(page, /selectSubscriptionTlsProfile\(event\.target\.value\)/);
  assert.match(page, /selectCdnDeploymentTlsProfile\([\s\S]*deploymentIndex/);
  assert.match(page, /Домен раздачи CDN/);
  assert.match(page, /DNS-имя origin/);
  assert.match(page, /subscription-address-grid-separate/);
  assert.match(css, /\.subscription-address-grid-separate\s*\{\s*grid-template-columns:\s*minmax\(140px, 0\.65fr\) minmax\(240px, 1\.35fr\)/);
  const separate = page.match(/subscription-address-grid-separate[\s\S]*?<\/div>\s*\)\s*:\s*null/);
  assert.ok(separate, "separate CDN grid must exist");
  assert.ok(
    separate[0].indexOf("TLS-профиль origin") < separate[0].indexOf("DNS-имя origin"),
    "TLS profile must precede the origin hostname in the separate CDN grid",
  );
  assert.match(page, /const configuredSubscriptionHostname = configuredSubscriptionHostnameValue;/);
  assert.doesNotMatch(page, /configuredSubscriptionHostnameValue \|\| configuredStatusHostname/);
});

test("opening subscription settings hydrates legacy CDN and direct origin before the dialog renders", async () => {
  const page = await readFile(new URL("../app/page.tsx", import.meta.url), "utf8");
  const parsed = ts.createSourceFile("page.tsx", page, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  let opener = "";
  function visit(node) {
    if (ts.isFunctionDeclaration(node) && node.name?.text === "openSubscriptionEndpointDialog") {
      opener = node.getText(parsed);
    }
    ts.forEachChild(node, visit);
  }
  visit(parsed);
  assert.ok(opener, "subscription dialog opener must exist");
  assert.match(opener, /setSubscriptionHostname\(initialSubscriptionHostname\)/);
  assert.match(opener, /setSubscriptionCdnHostname\(configuredSubscriptionCdnHostname\)/);
  assert.match(opener, /configuredSubscriptionCdnHostname[\s\S]*"subscription-cdn"/);
  assert.match(opener, /setSubscriptionEndpointDialogOpen\(true\)/);
  assert.match(page, /onClick=\{openSubscriptionEndpointDialog\}/);
});

test("Connections cannot render from defaults before the current draft is hydrated", async () => {
  const page = await readFile(new URL("../app/page.tsx", import.meta.url), "utf8");
  assert.match(
    page,
    /screen === "connections"[\s\S]*?configurationHydrated \? \([\s\S]*?<Connections[\s\S]*?Загружаю настройки подключений…/,
  );
});

test("SetupWizard retains an explicit separate origin while saving an incomplete draft", async () => {
  const page = await readFile(new URL("../app/page.tsx", import.meta.url), "utf8");
  const parsed = ts.createSourceFile("page.tsx", page, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  let wizardText = "";
  function visit(node) {
    if (ts.isFunctionDeclaration(node) && node.name?.text === "SetupWizard") wizardText = node.getText(parsed);
    ts.forEachChild(node, visit);
  }
  visit(parsed);
  assert.ok(wizardText, "SetupWizard must exist");
  assert.match(wizardText, /\.\.\.ingress,[\s\S]*subscription_hostname:\s*subscriptionHost/);
  assert.doesNotMatch(wizardText, /subscription_origin_server_name:\s*""/);
});
