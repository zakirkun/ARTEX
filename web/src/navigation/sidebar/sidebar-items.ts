import {
  Activity,
  Ban,
  BellRing,
  Bot,
  Brain,
  Bug,
  ClipboardList,
  FolderOpen,
  FolderSync,
  LayoutDashboard,
  type LucideIcon,
  MessageSquare,
  Network,
  Plug,
  Radio,
  ScrollText,
  Settings2,
  ShieldAlert,
  Sparkles,
  Target,
  Terminal,
  Wrench,
} from "lucide-react";

import type { TranslationKey } from "@/i18n/dictionary";

export type NavBadge = "new" | "soon";

export interface NavSubItem {
  id: string;
  /** Translation key resolved through t() at render time. */
  titleKey: TranslationKey;
  url: string;
  icon?: LucideIcon;
  badge?: NavBadge;
  disabled?: boolean;
  newTab?: boolean;
}

interface NavItemBase {
  id: string;
  /** Translation key resolved through t() at render time. */
  titleKey: TranslationKey;
  icon?: LucideIcon;
  badge?: NavBadge;
  disabled?: boolean;
  newTab?: boolean;
}

export interface NavMainLinkItem extends NavItemBase {
  url: string;
  subItems?: never;
}

export interface NavMainParentItem extends NavItemBase {
  subItems: NavSubItem[];
}

export type NavMainItem = NavMainLinkItem | NavMainParentItem;

export interface NavGroup {
  id: number;
  /** Translation key for the group label, or undefined for no label. */
  labelKey?: TranslationKey;
  items: NavMainItem[];
}

/**
 * The navigation tree. Titles are translation keys, not display strings: the
 * sidebar resolves them through the active locale at render time, so switching
 * to Bahasa Indonesia relabels the whole menu without touching this file.
 */
export const sidebarItems: NavGroup[] = [
  {
    id: 1,
    labelKey: "nav.groupFunctions",
    items: [
      { id: "dashboard", titleKey: "nav.dashboard", url: "/dashboard", icon: LayoutDashboard },
      { id: "chat", titleKey: "nav.chat", url: "/chat", icon: MessageSquare },
      { id: "tasks", titleKey: "nav.tasks", url: "/function/tasks", icon: Target },
      { id: "findings", titleKey: "nav.findings", url: "/function/findings", icon: Bug },
      { id: "traffic", titleKey: "nav.traffic", url: "/function/traffic", icon: Activity },
      { id: "commands", titleKey: "nav.commands", url: "/function/commands", icon: Terminal },
      { id: "llm-records", titleKey: "nav.llmRecords", url: "/function/llm-records", icon: Radio },
      { id: "assets", titleKey: "nav.assets", url: "/function/assets", icon: Network },
      { id: "sync", titleKey: "nav.sync", url: "/function/sync", icon: FolderSync },
      { id: "workspace", titleKey: "nav.workspace", url: "/function/workspace", icon: FolderOpen },
    ],
  },
  {
    id: 2,
    labelKey: "nav.groupSystem",
    items: [
      { id: "llm", titleKey: "nav.llm", url: "/system/llm", icon: Brain },
      { id: "agents", titleKey: "nav.agents", url: "/system/agents", icon: Bot },
      { id: "mcp", titleKey: "nav.mcp", url: "/system/mcp", icon: Plug },
      { id: "skills", titleKey: "nav.skills", url: "/system/skills", icon: Sparkles },
      { id: "tools", titleKey: "nav.tools", url: "/system/tools", icon: Wrench },
      { id: "notify", titleKey: "nav.notify", url: "/system/notify", icon: BellRing },
      { id: "intercept", titleKey: "nav.intercept", url: "/system/intercept", icon: ShieldAlert },
      { id: "asset-intercept", titleKey: "nav.assetIntercept", url: "/system/intercept/assets", icon: Ban },
      { id: "approvals", titleKey: "nav.approvals", url: "/system/intercept/approvals", icon: ClipboardList },
      { id: "logs", titleKey: "nav.logs", url: "/system/logs", icon: ScrollText },
      { id: "settings", titleKey: "nav.settings", url: "/system/settings", icon: Settings2 },
    ],
  },
];
