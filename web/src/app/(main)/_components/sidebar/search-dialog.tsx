"use client";

import * as React from "react";

import { useRouter } from "next/navigation";

import { Search } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Command,
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
} from "@/components/ui/command";
import type { TranslationKey } from "@/i18n/dictionary";
import { useTranslation } from "@/i18n/i18n-provider";
import type { NavMainItem } from "@/navigation/sidebar/sidebar-items";
import { sidebarItems } from "@/navigation/sidebar/sidebar-items";

type SearchItem = {
  id: string;
  groupKey: TranslationKey;
  labelKey: TranslationKey;
  url: string;
  icon?: NavMainItem["icon"];
  disabled?: boolean;
  newTab?: boolean;
};

// Groups are identified by the sub-item's parent title key; this set lets
// getSubItemGroup tell "a group heading" apart from "a parent item used as a heading".
const MAIN_GROUP_KEYS = sidebarItems.flatMap((group) => (group.labelKey ? [group.labelKey] : []));

function getSubItemGroupKey(groupLabelKey: TranslationKey | undefined, parentTitleKey: TranslationKey): TranslationKey {
  return MAIN_GROUP_KEYS.includes(parentTitleKey) ? (groupLabelKey ?? "common.other") : parentTitleKey;
}

const searchItems: SearchItem[] = sidebarItems.flatMap((group) =>
  group.items.flatMap((item) => {
    if (item.subItems) {
      return item.subItems.map((sub) => ({
        id: sub.id,
        groupKey: getSubItemGroupKey(group.labelKey, item.titleKey),
        labelKey: sub.titleKey,
        url: sub.url,
        icon: item.icon,
        disabled: sub.disabled,
        newTab: sub.newTab,
      }));
    }
    return [
      {
        id: item.id,
        groupKey: group.labelKey ?? "common.other",
        labelKey: item.titleKey,
        url: item.url,
        icon: item.icon,
        disabled: item.disabled,
        newTab: item.newTab,
      },
    ];
  }),
);

function getAvailableItems(items: SearchItem[]) {
  return items.filter((item) => !item.disabled && !item.url.includes("coming-soon"));
}

const recommendations = getAvailableItems(searchItems);

function groupBy(items: SearchItem[]) {
  const groups = [...new Set(items.map((item) => item.groupKey))];
  return groups.map((groupKey) => ({
    groupKey,
    items: items.filter((item) => item.groupKey === groupKey),
  }));
}

export function SearchDialog() {
  const { t } = useTranslation();
  const [open, setOpen] = React.useState(false);
  const [query, setQuery] = React.useState("");
  const router = useRouter();

  React.useEffect(() => {
    const down = (e: KeyboardEvent) => {
      if (e.key === "j" && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setOpen((prev) => !prev);
      }
    };
    document.addEventListener("keydown", down);
    return () => document.removeEventListener("keydown", down);
  }, []);

  const handleOpenChange = (value: boolean) => {
    setOpen(value);
    if (!value) setQuery("");
  };

  const handleSelect = (item: SearchItem) => {
    if (item.disabled) return;
    handleOpenChange(false);
    if (item.newTab) {
      window.open(item.url, "_blank", "noopener,noreferrer");
    } else {
      router.push(item.url);
    }
  };

  const renderGroups = (items: SearchItem[]) =>
    groupBy(items).map(({ groupKey, items: groupItems }, index) => (
      <React.Fragment key={groupKey}>
        {index > 0 && <CommandSeparator />}
        <CommandGroup heading={t(groupKey)}>
          {groupItems.map((item) => (
            <CommandItem
              disabled={item.disabled}
              key={`${groupKey}-${item.id}`}
              value={`${t(groupKey)} ${t(item.labelKey)}`}
              onSelect={() => handleSelect(item)}
            >
              <span className="flex min-w-0 items-center gap-2">
                {item.icon && <item.icon />}
                <span className="truncate">{t(item.labelKey)}</span>
              </span>
            </CommandItem>
          ))}
        </CommandGroup>
      </React.Fragment>
    ));

  return (
    <>
      <Button
        onClick={() => handleOpenChange(true)}
        variant="link"
        className="px-0! font-normal text-muted-foreground hover:no-underline"
      >
        <Search data-icon="inline-start" />
        {t("common.search")}
        <kbd className="inline-flex h-5 select-none items-center gap-1 rounded border bg-muted px-1.5 font-medium text-[10px]">
          <span className="text-xs">⌘</span>J
        </kbd>
      </Button>
      <CommandDialog open={open} onOpenChange={handleOpenChange}>
        <Command>
          <CommandInput placeholder={t("search.placeholder")} value={query} onValueChange={setQuery} />
          <CommandList>
            <CommandEmpty>{t("search.noResults")}</CommandEmpty>
            {query ? renderGroups(searchItems) : renderGroups(recommendations)}
          </CommandList>
        </Command>
      </CommandDialog>
    </>
  );
}
