import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const page = readFileSync(new URL("../app/page.tsx", import.meta.url), "utf8");
const api = readFileSync(
  new URL("../internal/controlplane/api.go", import.meta.url),
  "utf8",
);

test("login form uses a native same-origin submission with password-manager semantics", () => {
  const loginPanel = page.slice(
    page.indexOf("function LoginPanel("),
    page.indexOf("export default function Home()"),
  );

  assert.match(
    loginPanel,
    /<form[\s\S]*?className="login-form"[\s\S]*?action="\/api\/v1\/auth\/login-form"[\s\S]*?method="post"[\s\S]*?autoComplete=\{rememberCredentials \? "on" : "off"\}/,
  );
  assert.match(
    loginPanel,
    /htmlFor="username"[\s\S]*?id="username"[\s\S]*?name="username"[\s\S]*?type="text"[\s\S]*?autoComplete=\{rememberCredentials \? "username" : "off"\}/,
  );
  assert.match(
    loginPanel,
    /htmlFor="current-password"[\s\S]*?id="current-password"[\s\S]*?name="password"[\s\S]*?type="password"[\s\S]*?autoComplete=\{rememberCredentials \? "current-password" : "off"\}/,
  );
  assert.match(
    loginPanel,
    /id="remember-credentials"[\s\S]*?name="remember"[\s\S]*?type="checkbox"[\s\S]*?checked=\{rememberCredentials\}/,
  );
  assert.doesNotMatch(loginPanel, /preventDefault\(/);
  assert.doesNotMatch(loginPanel, /offerPasswordSave|await login\(/);
});

test("native login endpoint authenticates and redirects without exposing the password", () => {
  assert.match(
    api,
    /HandleFunc\("POST "\+apiPrefix\+"\/auth\/login-form", server\.authLoginForm\)/,
  );
  assert.match(
    api,
    /func \(server \*Server\) authLoginForm[\s\S]*?request\.PostForm\.Get\("username"\)[\s\S]*?request\.PostForm\.Get\("password"\)/,
  );
  assert.match(
    api,
    /server\.setSessionCookie\(response, token\)[\s\S]*?http\.Redirect\(response, request, "\/#\/overview", http\.StatusSeeOther\)/,
  );
  assert.match(
    page,
    /searchParams\.get\("login_error"\)[\s\S]*?searchParams\.delete\("login_error"\)[\s\S]*?history\.replaceState/,
  );
  assert.doesNotMatch(api, /login_error=.*password/);
});
