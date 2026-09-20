import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import ts from "typescript";
import * as React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { normalizeLocalizedSource } from "./source-localization.mjs";

const page = normalizeLocalizedSource(await readFile(new URL("../app/page.tsx", import.meta.url), "utf8"));
const parsed = ts.createSourceFile("page.tsx", page, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
let sharedTLSFields;

function findSharedTLSFields(node) {
  if (
    ts.isConditionalExpression(node) &&
    node.condition.getText(parsed) === "sharedTlsManagedKind" &&
    node.whenTrue.getText(parsed).includes('name="tls_profile_id"')
  ) {
    sharedTLSFields = node;
  }
  ts.forEachChild(node, findSharedTLSFields);
}

findSharedTLSFields(parsed);
assert.ok(sharedTLSFields, "shared TLS profile fields must remain a conditional branch");

const renderSource = `
function renderSharedTLSFields(props) {
  const {
    sharedTlsManagedKind,
    cdnTransportKind,
    tlsProfiles,
    tlsProfileChoice,
    selectTransportTlsProfile,
    selectedTlsProfileComplete,
    asText,
    itemName,
  } = props;
  return (${sharedTLSFields.getText(parsed)});
}
`;
const compiled = ts.transpileModule(renderSource, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.React },
}).outputText;
const renderSharedTLSFields = new Function(
  "React",
  `const { Fragment } = React; ${compiled}; return renderSharedTLSFields;`,
)(React);

const readyProfile = {
  id: "ready",
  display_name: "Основной",
  certificate_secret_ref: "tls/ready/certificate.pem",
  private_key_secret_ref: "tls/ready/private.pem",
};
const incompleteProfile = { id: "incomplete", display_name: "Резервный" };

function render(choice, profiles = [readyProfile, incompleteProfile], sharedTlsManagedKind = true) {
  return renderToStaticMarkup(
    renderSharedTLSFields({
      sharedTlsManagedKind,
      cdnTransportKind: false,
      tlsProfiles: profiles,
      tlsProfileChoice: choice,
      selectTransportTlsProfile: () => {},
      selectedTlsProfileComplete: choice === "ready",
      asText: (value, fallback = "") =>
        typeof value === "string" ? value : fallback,
      itemName: (profile) => profile.display_name || profile.id,
    }),
  );
}

test("shared TLS transport renders only the existing profile choice", () => {
  const html = render("ready");

  assert.match(html, /name="tls_profile_id"/);
  assert.doesNotMatch(html, /name="origin_certificate"|name="origin_private_key"/);
  assert.doesNotMatch(html, /SecretStore|TLS-профиль «|Действует до|Создать новый TLS-профиль/);
});

test("incomplete profile points to TLS profiles without enabling inline certificate mutation", () => {
  const html = render("incomplete");
  assert.match(html, /Настройте сертификат в TLS-профилях/);
  assert.doesNotMatch(html, /origin_certificate|origin_private_key|tls_profile_name|SecretStore/);
});

test("shared TLS fields stay absent for transports managed elsewhere", () => {
  assert.equal(render("ready", [readyProfile, incompleteProfile], false), "");
});

test("empty TLS profile list directs setup to the TLS profile editor", () => {
  const html = render("", []);
  assert.match(html, /Создайте TLS-профиль в разделе TLS-профили/);
  assert.match(html, /name="tls_profile_id"[^>]*required=""/);
  assert.doesNotMatch(html, /Создать новый TLS-профиль|origin_certificate|tls_profile_name/);
});

test("unset transport TLS selection is derived from SNI instead of the first profile", () => {
  const connectionStart = page.indexOf("function ConnectionDialog(");
  const choiceStart = page.indexOf("const initialTlsProfileId", connectionStart);
  const choiceEnd = page.indexOf("const [tlsProfileChoice", choiceStart);
  const initialChoice = page.slice(choiceStart, choiceEnd);
  assert.match(initialChoice, /savedTlsProfileId \|\|/);
  assert.match(initialChoice, /tlsProfileIdForHostname\(tlsProfiles, persistedDirectTlsServerName, ""\)/);
  assert.doesNotMatch(initialChoice, /tlsProfiles\[0\]/);
});

test("connection submit does not create or update TLS profiles", () => {
  const dialogStart = page.indexOf("function ConnectionDialog(");
  const dialogEnd = page.indexOf("function Connections(", dialogStart);
  const dialog = page.slice(dialogStart, dialogEnd);
  assert.doesNotMatch(dialog, /originCertificateRef|originPrivateKeyRef|origin_certificate|origin_private_key/);
  assert.doesNotMatch(dialog, /createCollectionItem\("tls-profiles"|updateCollectionItem\(\s*"tls-profiles"/);
});

test("direct TLS SNI follows the selected certificate inside the existing field", () => {
  const dialogStart = page.indexOf("function ConnectionDialog(");
  const dialogEnd = page.indexOf("function Connections(", dialogStart);
  const dialog = page.slice(dialogStart, dialogEnd);
  assert.match(dialog, /certificateStatus\[asText\(profile\.id, ""\)\]/);
  assert.match(dialog, /hostnameAfterTLSProfileChange\(profile, current\)/);
  assert.match(dialog, /savedTlsProfileId \|\|[\s\S]*?tlsProfileIdForHostname\(tlsProfiles, persistedDirectTlsServerName, ""\)/);
  assert.match(dialog, /tlsProfileIdForHostname\(\s*tlsProfiles,\s*nextServerName,\s*tlsProfileChoice/);
  assert.match(dialog, /name="tls_server_name"[\s\S]*?value=\{directTlsServerName\}/);
  assert.match(dialog, /list="direct-tls-server-names"/);
  assert.match(dialog, /<datalist id="direct-tls-server-names">/);
  assert.doesNotMatch(dialog, /Имя из выбранного сертификата\./);
});
