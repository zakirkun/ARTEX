"use client";

import { LanguagesIcon } from "lucide-react";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { LOCALE_LABELS, LOCALE_VALUES, type Locale } from "@/i18n/config";
import { useI18n } from "@/i18n/i18n-provider";

/**
 * The language picker. Like the chat send-mode toggle it is a pure frontend
 * preference: it writes the locale cookie directly and never touches
 * /api/settings, so switching the interface language works on a static export.
 */
export function LanguageCard() {
  const { t, locale, setLocale } = useI18n();

  return (
    <Card className="mb-4 break-inside-avoid md:mb-6">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <LanguagesIcon className="size-4" />
          {t("settings.languageSection")}
        </CardTitle>
        <CardDescription>{t("settings.languageDescription")}</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="flex items-center justify-between gap-4">
          <Label htmlFor="i18n-locale">{t("language.title")}</Label>
          <Select value={locale} onValueChange={(v) => setLocale(v as Locale)}>
            <SelectTrigger id="i18n-locale" className="w-48">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {LOCALE_VALUES.map((value) => (
                <SelectItem key={value} value={value}>
                  {LOCALE_LABELS[value]}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </CardContent>
    </Card>
  );
}
