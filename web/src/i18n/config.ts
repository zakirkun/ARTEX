/**
 * Locale configuration for the interface language.
 *
 * Indonesian is the second shipped locale. The value lives in a cookie (like the
 * other preferences) so the boot script can set <html lang> before paint and the
 * provider can pick the dictionary on the client without a server round-trip.
 */

export const LOCALE_VALUES = ["en", "id"] as const;
export type Locale = (typeof LOCALE_VALUES)[number];

export const LOCALE_DEFAULT: Locale = "en";

/** Cookie / storage key and the data attribute mirrored onto <html>. */
export const LOCALE_KEY = "lang";
export const LOCALE_ATTR = "data-lang";

export function isLocale(v: string | null | undefined): v is Locale {
  return typeof v === "string" && (LOCALE_VALUES as readonly string[]).includes(v);
}

/** Native display name for each locale, used by the language switcher. */
export const LOCALE_LABELS: Record<Locale, string> = {
  en: "English",
  id: "Bahasa Indonesia",
};

/** The `lang` attribute value written to <html>, per locale. */
export const LOCALE_HTML_LANG: Record<Locale, string> = {
  en: "en",
  id: "id",
};
