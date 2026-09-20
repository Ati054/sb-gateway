"use client";

import { createContext, ReactNode, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { localizedText } from "./i18n-text";

export type Locale = "ru" | "en";

const LOCALE_STORAGE_KEY = "sb-gateway:locale";

const messages = {
  ru: {
    "language.title": "Выберите язык панели",
    "language.lead": "Язык можно изменить позже рядом с профилем администратора.",
    "language.russian": "Русский",
    "language.english": "English",
    "language.switchToEnglish": "Switch to English",
    "language.switchToRussian": "Переключить на русский",
    "document.title": "SB Gateway — управление VLESS на MikroTik",
    "document.description": "Локальная защищённая панель управления маршрутизацией, VLESS, CDN и отказоустойчивостью на MikroTik RouterOS.",
    "common.advanced": "Дополнительно",
    "common.cancel": "Отмена",
    "common.save": "Сохранить изменения",
    "common.retry": "Повторить",
    "shell.skip": "К основному содержимому",
    "shell.closeMenu": "Закрыть меню",
    "shell.openMenu": "Открыть меню",
    "shell.navigation": "Основная навигация",
    "shell.localNetwork": "Локальная сеть",
    "shell.logout": "Завершить сеанс",
    "status.error": "Ошибка получения статуса",
    "status.healthy": "Система работает",
    "status.unconfigured": "Ожидает настройки",
    "status.checking": "Состояние проверяется",
    "status.channel": "Канал",
    "status.core": "Ядро",
    "status.container": "Контейнер",
    "status.fromExport": "из экспорта",
    "status.notDetected": "не обнаружен",
    "status.notDefined": "не определено",
    "nav.overview.label": "Обзор",
    "nav.overview.short": "О",
    "nav.overview.description": "Состояние шлюза",
    "nav.clients.label": "Устройства",
    "nav.clients.short": "У",
    "nav.clients.description": "Локальные и удалённые",
    "nav.routing.label": "Маршрутизация",
    "nav.routing.short": "М",
    "nav.routing.description": "Правила и страны",
    "nav.connections.label": "Подключения",
    "nav.connections.short": "П",
    "nav.connections.description": "Входы и провайдеры",
    "nav.operations.label": "Эксплуатация",
    "nav.operations.short": "Э",
    "nav.operations.description": "Проверки и откат",
    "nav.settings.label": "Настройки",
    "nav.settings.short": "Н",
    "nav.settings.description": "Доступ и безопасность",
    "regenerate.action": "Сбросить",
    "regenerate.title": "Выбрать сброс и пересоздание",
    "regenerate.group": "Что сбросить или пересоздать",
    "regenerate.httpPath": "HTTP-путь",
    "regenerate.grpc": "Имя gRPC",
    "regenerate.salamander": "Пароль Salamander",
    "transport.base": "Сброс и пересоздание",
    "transport.baseSafe": "Выберите изменения. Они выполнятся после сохранения.",
    "transport.reset": "Базовые параметры",
    "transport.resetStatus": "Будет выполнено:",
    "bootstrap.brand": "Первый защищённый запуск",
    "bootstrap.eyebrow": "Однократная настройка администратора",
    "bootstrap.title": "Создайте пароль локальной панели",
    "bootstrap.leadBefore": "Пользователь фиксирован:",
    "bootstrap.leadAfter": "Пароль хешируется локальным control plane и не возвращается в браузер.",
    "bootstrap.password": "Новый пароль · минимум 12 символов",
    "bootstrap.confirm": "Подтверждение пароля",
    "bootstrap.creating": "Создаю защищённый сеанс…",
    "bootstrap.create": "Создать администратора",
    "bootstrap.once": "Bootstrap работает только один раз",
    "bootstrap.onceText": "После создания пароля endpoint блокируется; дальнейший вход выполняется обычной формой.",
    "bootstrap.shortPassword": "Пароль должен содержать не менее 12 символов.",
    "bootstrap.mismatch": "Пароль и подтверждение не совпадают.",
    "login.invalid": "Неверный пользователь или пароль.",
    "login.rateLimited": "Слишком много попыток входа. Повторите позже.",
    "login.bootstrapRequired": "Сначала создайте администратора панели.",
    "login.failed": "Вход не выполнен. Повторите попытку.",
    "login.serverHttp": "Сервер вернул HTTP",
    "login.brand": "Локальное управление MikroTik",
    "login.checkingTitle": "Проверяем локальный сеанс",
    "login.offlineTitle": "Связь временно прервана",
    "login.title": "Вход в панель",
    "login.offlineLead": "Панель повторно подключается автоматически. Текущая маршрутизация продолжает работать.",
    "login.connecting": "Связываюсь с локальным API…",
    "login.offlineHelp": "Проверьте, что контейнер запущен и открыт локальный HTTPS-порт 9443.",
    "login.username": "Пользователь",
    "login.password": "Пароль",
    "login.remember": "Запомнить данные",
    "login.signingIn": "Вхожу…",
    "login.signIn": "Войти",
  },
  en: {
    "language.title": "Choose the panel language",
    "language.lead": "You can change it later next to the administrator profile.",
    "language.russian": "Русский",
    "language.english": "English",
    "language.switchToEnglish": "Switch to English",
    "language.switchToRussian": "Переключить на русский",
    "document.title": "SB Gateway — VLESS Management for MikroTik",
    "document.description": "Secure local management of routing, VLESS, CDNs, and failover on MikroTik RouterOS.",
    "common.advanced": "Advanced",
    "common.cancel": "Cancel",
    "common.save": "Save changes",
    "common.retry": "Retry",
    "shell.skip": "Skip to main content",
    "shell.closeMenu": "Close menu",
    "shell.openMenu": "Open menu",
    "shell.navigation": "Main navigation",
    "shell.localNetwork": "Local network",
    "shell.logout": "Sign out",
    "status.error": "Could not load status",
    "status.healthy": "System operational",
    "status.unconfigured": "Waiting for setup",
    "status.checking": "Checking status",
    "status.channel": "Channel",
    "status.core": "Core",
    "status.container": "Container",
    "status.fromExport": "from export",
    "status.notDetected": "not detected",
    "status.notDefined": "not defined",
    "nav.overview.label": "Overview",
    "nav.overview.short": "O",
    "nav.overview.description": "Gateway status",
    "nav.clients.label": "Devices",
    "nav.clients.short": "D",
    "nav.clients.description": "Local and remote",
    "nav.routing.label": "Routing",
    "nav.routing.short": "R",
    "nav.routing.description": "Rules and countries",
    "nav.connections.label": "Connections",
    "nav.connections.short": "C",
    "nav.connections.description": "Inbound and providers",
    "nav.operations.label": "Operations",
    "nav.operations.short": "O",
    "nav.operations.description": "Checks and rollback",
    "nav.settings.label": "Settings",
    "nav.settings.short": "S",
    "nav.settings.description": "Access and security",
    "regenerate.action": "Reset",
    "regenerate.title": "Choose what to reset or regenerate",
    "regenerate.group": "Items to reset or regenerate",
    "regenerate.httpPath": "HTTP path",
    "regenerate.grpc": "gRPC name",
    "regenerate.salamander": "Salamander password",
    "transport.base": "Reset and regenerate",
    "transport.baseSafe": "Choose the changes to apply when you save.",
    "transport.reset": "Default parameters",
    "transport.resetStatus": "Pending:",
    "bootstrap.brand": "First secure launch",
    "bootstrap.eyebrow": "One-time administrator setup",
    "bootstrap.title": "Create a local panel password",
    "bootstrap.leadBefore": "The username is fixed:",
    "bootstrap.leadAfter": "The local control plane hashes the password and never returns it to the browser.",
    "bootstrap.password": "New password · at least 12 characters",
    "bootstrap.confirm": "Confirm password",
    "bootstrap.creating": "Creating secure session…",
    "bootstrap.create": "Create administrator",
    "bootstrap.once": "Bootstrap runs only once",
    "bootstrap.onceText": "After the password is created, the endpoint is disabled and the regular sign-in form is used.",
    "bootstrap.shortPassword": "The password must contain at least 12 characters.",
    "bootstrap.mismatch": "The password and confirmation do not match.",
    "login.invalid": "Incorrect username or password.",
    "login.rateLimited": "Too many sign-in attempts. Try again later.",
    "login.bootstrapRequired": "Create the panel administrator first.",
    "login.failed": "Sign-in failed. Try again.",
    "login.serverHttp": "Server returned HTTP",
    "login.brand": "Local MikroTik management",
    "login.checkingTitle": "Checking the local session",
    "login.offlineTitle": "Connection temporarily unavailable",
    "login.title": "Sign in to the panel",
    "login.offlineLead": "The panel reconnects automatically. Current routing continues to work.",
    "login.connecting": "Connecting to the local API…",
    "login.offlineHelp": "Check that the container is running and local HTTPS port 9443 is open.",
    "login.username": "Username",
    "login.password": "Password",
    "login.remember": "Remember credentials",
    "login.signingIn": "Signing in…",
    "login.signIn": "Sign in",
  },
} as const;

export type MessageKey = keyof typeof messages.ru;

type LanguageContextValue = {
  locale: Locale;
  setLocale: (locale: Locale) => void;
  t: (key: MessageKey) => string;
  tr: (source: string, values?: Record<string, string | number>) => string;
};

const LanguageContext = createContext<LanguageContextValue | null>(null);

function LanguageChoice({ onChoose }: { onChoose: (locale: Locale) => void }) {
  return (
    <main className="language-choice-shell">
      <section className="language-choice-card" aria-labelledby="language-choice-title">
        <span className="brand-mark">SB</span>
        <h1 id="language-choice-title">Выберите язык / Choose language</h1>
        <p>Язык можно изменить позже. You can change it later.</p>
        <div className="language-choice-actions">
          <button className="button button-primary" type="button" onClick={() => onChoose("ru")}>
            Русский
          </button>
          <button className="button button-secondary" type="button" onClick={() => onChoose("en")}>
            English
          </button>
        </div>
      </section>
    </main>
  );
}

export function LanguageProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>("ru");
  const [needsChoice, setNeedsChoice] = useState(false);

  useEffect(() => {
    let active = true;
    queueMicrotask(() => {
      if (!active) return;
      const saved = window.localStorage.getItem(LOCALE_STORAGE_KEY);
      if (saved === "ru" || saved === "en") {
        setLocaleState(saved);
        return;
      }
      setNeedsChoice(true);
    });
    return () => {
      active = false;
    };
  }, []);

  const setLocale = useCallback((nextLocale: Locale) => {
    window.localStorage.setItem(LOCALE_STORAGE_KEY, nextLocale);
    setLocaleState(nextLocale);
    setNeedsChoice(false);
  }, []);

  useEffect(() => {
    document.documentElement.lang = locale;
    document.title = messages[locale]["document.title"];
    document
      .querySelector<HTMLMetaElement>('meta[name="description"]')
      ?.setAttribute("content", messages[locale]["document.description"]);
  }, [locale, setLocale]);

  const value = useMemo<LanguageContextValue>(() => {
    return {
      locale,
      setLocale,
      t: (key) => messages[locale][key],
      tr: (source, values = {}) =>
        Object.entries(values).reduce(
          (text, [key, value]) => text.replaceAll(`{${key}}`, String(value)),
          localizedText(source, locale),
        ),
    };
  }, [locale, setLocale]);

  return (
    <LanguageContext.Provider value={value}>
      {children}
      {needsChoice ? <LanguageChoice onChoose={setLocale} /> : null}
    </LanguageContext.Provider>
  );
}

export function useLanguage(): LanguageContextValue {
  const value = useContext(LanguageContext);
  if (!value) throw new Error("useLanguage must be used inside LanguageProvider");
  return value;
}
