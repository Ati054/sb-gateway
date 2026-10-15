"use client";

import { GatewayApiError, bootstrapAdministrator, session } from "../api-client";
import { type MessageKey, useLanguage } from "../i18n";
import { errorMessage } from "./shared";
import { GatewayConsole } from "./shell";
import { FormEvent, useCallback, useEffect, useRef, useState } from "react";

function BootstrapPanel({
  onAuthenticated,
}: {
  onAuthenticated: (username: string) => void;
}) {
  const { locale, setLocale, t } = useLanguage();
  const passwordRef = useRef<HTMLInputElement>(null);
  const confirmationRef = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const password = passwordRef.current?.value ?? "";
    const confirmation = confirmationRef.current?.value ?? "";
    if (password.length < 12) {
      setMessage(t("bootstrap.shortPassword"));
      passwordRef.current?.focus();
      return;
    }
    if (password !== confirmation) {
      setMessage(t("bootstrap.mismatch"));
      confirmationRef.current?.focus();
      return;
    }
    if (passwordRef.current) passwordRef.current.value = "";
    if (confirmationRef.current) confirmationRef.current.value = "";
    setBusy(true);
    setMessage("");
    try {
      const response = await bootstrapAdministrator(password, confirmation);
      onAuthenticated(response.user?.username ?? "admin");
    } catch (error) {
      setMessage(errorMessage(error));
      passwordRef.current?.focus();
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="login-shell">
      <section className="login-card" aria-labelledby="bootstrap-title">
        <button
          className="login-language-toggle"
          type="button"
          onClick={() => setLocale(locale === "ru" ? "en" : "ru")}
          aria-label={locale === "ru" ? t("language.switchToEnglish") : t("language.switchToRussian")}
        >
          {locale.toUpperCase()}
        </button>
        <div className="brand login-brand">
          <span className="brand-mark">SB</span>
          <div>
            <strong>Gateway</strong>
            <small>{t("bootstrap.brand")}</small>
          </div>
        </div>
        <p className="eyebrow">{t("bootstrap.eyebrow")}</p>
        <h1 id="bootstrap-title">{t("bootstrap.title")}</h1>
        <p className="login-lead">
          {t("bootstrap.leadBefore")} <code>admin</code>. {t("bootstrap.leadAfter")}
        </p>
        <form className="login-form" onSubmit={submit}>
          <label className="field">
            {t("bootstrap.password")}
            <input
              ref={passwordRef}
              type="password"
              autoComplete="new-password"
              minLength={12}
              required
              autoFocus
            />
          </label>
          <label className="field">
            {t("bootstrap.confirm")}
            <input
              ref={confirmationRef}
              type="password"
              autoComplete="new-password"
              minLength={12}
              required
            />
          </label>
          {message ? (
            <div className="inline-result inline-result-error" role="alert">
              <span>!</span>
              {message}
            </div>
          ) : null}
          <button className="button button-primary" type="submit" disabled={busy}>
            {busy ? t("bootstrap.creating") : t("bootstrap.create")}
          </button>
        </form>
        <aside className="notice notice-safe">
          <span className="notice-icon">✓</span>
          <div>
            <strong>{t("bootstrap.once")}</strong>
            <p>{t("bootstrap.onceText")}</p>
          </div>
        </aside>
      </section>
    </main>
  );
}

function LoginPanel({
  state,
  initialMessage,
  onRetry,
}: {
  state: "checking" | "unauthenticated" | "offline";
  initialMessage: string;
  onRetry: () => void;
}) {
  const { locale, setLocale, t } = useLanguage();
  const [busy, setBusy] = useState(false);
  const [rememberCredentials, setRememberCredentials] = useState(true);

  function beginNativeSubmit() {
    setBusy(true);
  }

  return (
    <main className="login-shell">
      <section className="login-card" aria-labelledby="login-title">
        <button
          className="login-language-toggle"
          type="button"
          onClick={() => setLocale(locale === "ru" ? "en" : "ru")}
          aria-label={locale === "ru" ? t("language.switchToEnglish") : t("language.switchToRussian")}
        >
          {locale.toUpperCase()}
        </button>
        <div className="brand login-brand">
          <span className="brand-mark">SB</span>
          <div>
            <strong>Gateway</strong>
            <small>{t("login.brand")}</small>
          </div>
        </div>
        <p className="eyebrow">HTTPS · management LAN</p>
        <h1 id="login-title">
          {state === "checking"
            ? t("login.checkingTitle")
            : state === "offline"
              ? t("login.offlineTitle")
              : t("login.title")}
        </h1>
        {state === "offline" ? <p className="login-lead">{t("login.offlineLead")}</p> : null}
        {state === "checking" ? (
          <div className="login-progress" role="status">
            <span className="spinner" />
            {t("login.connecting")}
          </div>
        ) : state === "offline" ? (
          <>
            <div className="inline-result inline-result-error" role="alert">
              <span>!</span>
              {initialMessage ||
                t("login.offlineHelp")}
            </div>
            <button className="button button-primary" onClick={onRetry}>
              {t("common.retry")}
            </button>
          </>
        ) : (
          <form
            className="login-form"
            action="/api/v1/auth/login-form"
            method="post"
            onSubmit={beginNativeSubmit}
            autoComplete={rememberCredentials ? "on" : "off"}
          >
            <label className="field" htmlFor="username">
              {t("login.username")}
              <input
                id="username"
                name="username"
                type="text"
                autoComplete={rememberCredentials ? "username" : "off"}
                autoCapitalize="none"
                spellCheck={false}
                required
                autoFocus
              />
            </label>
            <label className="field" htmlFor="current-password">
              {t("login.password")}
              <input
                id="current-password"
                name="password"
                type="password"
                autoComplete={rememberCredentials ? "current-password" : "off"}
                required
              />
            </label>
            <label className="login-remember" htmlFor="remember-credentials">
              <input
                id="remember-credentials"
                name="remember"
                type="checkbox"
                autoComplete="off"
                checked={rememberCredentials}
                onChange={(event) => setRememberCredentials(event.target.checked)}
              />
              <span>{t("login.remember")}</span>
            </label>
            {initialMessage ? (
              <div className="inline-result inline-result-error" role="alert">
                <span>!</span>
                {initialMessage}
              </div>
            ) : null}
            <button
              className="button button-primary"
              type="submit"
              disabled={busy}
            >
              {busy ? t("login.signingIn") : t("login.signIn")}
            </button>
          </form>
        )}
      </section>
    </main>
  );
}

function loginFailureMessage(
  code: string | null,
  t: (key: MessageKey) => string,
): string {
  if (code === "invalid_credentials") return t("login.invalid");
  if (code === "login_rate_limited") {
    return t("login.rateLimited");
  }
  if (code === "bootstrap_required") {
    return t("login.bootstrapRequired");
  }
  return code ? t("login.failed") : "";
}

export function GatewayHome() {
  const { t } = useLanguage();
  const [authState, setAuthState] = useState<
    | "checking"
    | "authenticated"
    | "bootstrap"
    | "unauthenticated"
    | "offline"
  >("checking");
  const [username, setUsername] = useState("");
  const [authMessage, setAuthMessage] = useState(() =>
    typeof window === "undefined"
      ? ""
      : loginFailureMessage(
          new URL(window.location.href).searchParams.get("login_error"),
          t,
        ),
  );
  const [sessionAttempt, setSessionAttempt] = useState(0);
  const endSession = useCallback(() => {
    setUsername("");
    setAuthState("unauthenticated");
  }, []);

  useEffect(() => {
    const current = new URL(window.location.href);
    if (!current.searchParams.has("login_error")) return;
    current.searchParams.delete("login_error");
    window.history.replaceState(window.history.state, "", current);
  }, []);

  useEffect(() => {
    let active = true;
    session()
      .then((response) => {
        if (!active) return;
        if (response.authenticated) {
          setUsername(
            response.user?.username ?? response.username ?? "Администратор",
          );
          setAuthState("authenticated");
        } else if (response.bootstrap_required) {
          setAuthState("bootstrap");
        } else {
          setAuthState("unauthenticated");
        }
      })
      .catch((error) => {
        if (!active) return;
        if (error instanceof GatewayApiError && error.status === 401) {
          setAuthState("unauthenticated");
          return;
        }
        setAuthMessage(
          error instanceof GatewayApiError
            ? `${t("login.serverHttp")} ${error.status}`
            : errorMessage(error),
        );
        setAuthState("offline");
      });
    return () => {
      active = false;
    };
  }, [sessionAttempt, t]);

  useEffect(() => {
    if (authState !== "offline") return;
    const timer = window.setTimeout(() => {
      setAuthState("checking");
      setAuthMessage("");
      setSessionAttempt((current) => current + 1);
    }, 4_000);
    return () => window.clearTimeout(timer);
  }, [authState]);

  if (authState === "bootstrap") {
    return (
      <BootstrapPanel
        onAuthenticated={(name) => {
          setUsername(name);
          setAuthState("authenticated");
        }}
      />
    );
  }

  if (authState !== "authenticated") {
    return (
      <LoginPanel
        state={authState}
        initialMessage={authMessage}
        onRetry={() => {
          setAuthState("checking");
          setAuthMessage("");
          setSessionAttempt((current) => current + 1);
        }}
      />
    );
  }

  return (
    <GatewayConsole
      username={username}
      onSessionEnded={endSession}
    />
  );
}
