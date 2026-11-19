import type { Locale } from "./config";
import en from "./locales/en.json";
import id from "./locales/id.json";

/**
 * The dictionary shape is taken from the English file, so every other locale
 * must match its keys exactly at compile time. A missing key in `id.json` is a
 * type error, not a silent fallback, which keeps translations honest.
 */
export type Dictionary = typeof en;

export const DICTIONARIES: Record<Locale, Dictionary> = {
  en,
  id: id as Dictionary,
};

/**
 * A flat dot-path key into the dictionary, e.g. "nav.dashboard". Derived from
 * the English object so editors autocomplete and a typo fails the build.
 */
type Leaf<T, Prefix extends string = ""> = {
  [K in keyof T & string]: T[K] extends string ? `${Prefix}${K}` : Leaf<T[K], `${Prefix}${K}.`>;
}[keyof T & string];

export type TranslationKey = Leaf<Dictionary>;

/**
 * Resolve a dot-path key against a dictionary, returning the key itself when the
 * path is missing. Returning the key (rather than throwing or blanking) makes an
 * untranslated string visible on screen instead of crashing the render, which is
 * what a translator needs to see.
 */
export function lookup(dict: Dictionary, key: string): string {
  const parts = key.split(".");
  let cur: unknown = dict;
  for (const part of parts) {
    if (cur && typeof cur === "object" && part in (cur as Record<string, unknown>)) {
      cur = (cur as Record<string, unknown>)[part];
    } else {
      return key;
    }
  }
  return typeof cur === "string" ? cur : key;
}
