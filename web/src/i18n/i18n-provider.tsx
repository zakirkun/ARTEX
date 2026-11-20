"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";

import { setClientCookie } from "@/lib/cookie.client";

import { isLocale, LOCALE_ATTR, LOCALE_DEFAULT, LOCALE_HTML_LANG, LOCALE_KEY, type Locale } from "./config";
import { DICTIONARIES, type Dictionary, lookup, type TranslationKey } from "./dictionary";

type I18nContextValue = {
  locale: Locale;
  setLocale: (locale: Locale) => void;
  dict: Dictionary;
  t: (key: TranslationKey) => string;
};

const I18nContext = createContext<I18nContextValue | null>(null);

/**
 * I18nProvider reads the initial locale from the cookie written by the boot
 * script (or the server-rendered default), exposes a `t()` function, and keeps
 * <html lang> and the cookie in sync when the locale changes.
 *
 * It is client-only: the app is statically exportable, so there is no Node
 * request to read a cookie from on the server; the boot script sets <html lang>
 * pre-hydration and this provider takes over after mount. That avoids a
 * hydration mismatch while still letting the first paint use the right language.
 */
export function I18nProvider({ children, initialLocale }: { children: React.ReactNode; initialLocale: Locale }) {
  const [locale, setLocaleState] = useState<Locale>(initialLocale);

  // After mount, prefer the cookie over the server-rendered default so a saved
  // Indonesian choice is honoured even though RootLayout rendered English. This
  // runs exactly once: the cookie is read directly, so the effect has no reactive
  // dependency on `locale` (reading it via the functional updater avoids adding
  // `locale` to the deps, which would re-run the effect on every change).
  useEffect(() => {
    const fromCookie = typeof document !== "undefined" ? readLocaleCookie() : null;
    if (fromCookie) {
      setLocaleState((prev) => (prev === fromCookie ? prev : fromCookie));
    }
  }, []);

  // Keep the document in step with the locale.
  useEffect(() => {
    if (typeof document === "undefined") return;
    document.documentElement.lang = LOCALE_HTML_LANG[locale];
    document.documentElement.setAttribute(LOCALE_ATTR, locale);
  }, [locale]);

  const setLocale = useCallback((next: Locale) => {
    setLocaleState(next);
    setClientCookie(LOCALE_KEY, next);
  }, []);

  const dict = DICTIONARIES[locale];
  const t = useCallback((key: TranslationKey) => lookup(dict, key), [dict]);

  const value = useMemo<I18nContextValue>(() => ({ locale, setLocale, dict, t }), [locale, setLocale, dict, t]);

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

function readLocaleCookie(): Locale | null {
  const raw = document.cookie
    .split("; ")
    .find((row) => row.startsWith(`${LOCALE_KEY}=`))
    ?.split("=")[1];
  const decoded = raw ? decodeURIComponent(raw) : null;
  return isLocale(decoded) ? decoded : null;
}

export function useI18n(): I18nContextValue {
  const ctx = useContext(I18nContext);
  if (!ctx) throw new Error("useI18n must be used within I18nProvider");
  return ctx;
}

/** Convenience: just the translate function. */
export function useTranslation(): { t: (key: TranslationKey) => string; locale: Locale } {
  const { t, locale } = useI18n();
  return { t, locale };
}

export { LOCALE_DEFAULT };
