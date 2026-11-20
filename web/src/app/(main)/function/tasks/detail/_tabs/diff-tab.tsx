"use client";

import * as React from "react";

import { AlertTriangleIcon, RefreshCwIcon } from "lucide-react";

import { StatusBadge } from "@/components/status-badge";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from "@/components/ui/empty";
import { Skeleton } from "@/components/ui/skeleton";
import { api } from "@/lib/api";
import type { Task, TaskDiff, TaskDiffEntry } from "@/lib/types";

function entryLabel(entry: TaskDiffEntry) {
  return entry.name?.trim() || entry.vulnclass.trim() || "Uncategorized";
}

// Bucket ordering is deliberate: regressed first because a fix that did not hold is
// the highest-signal outcome of comparing two runs, then new, then persisting, and
// resolved last — resolved is the bucket whose trustworthiness depends on the head
// run's coverage.
const BUCKETS = [
  {
    key: "regressed" as const,
    title: "Regressed",
    description: "Previously marked fixed or resolved, and found again in this run.",
  },
  {
    key: "new" as const,
    title: "New",
    description: "Only in this run. Varied wording does not make a finding new — the match is by identity, not by title.",
  },
  {
    key: "persisting" as const,
    title: "Persisting",
    description: "Present in both runs and still open.",
  },
  {
    key: "resolved" as const,
    title: "Resolved",
    description: "In the earlier run, absent from this one.",
  },
];

export function DiffTab({ taskId }: { taskId: string }) {
  const [candidates, setCandidates] = React.useState<Task[]>([]);
  const [baseId, setBaseId] = React.useState("");
  const [diff, setDiff] = React.useState<TaskDiff | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState("");
  const [refreshVersion, setRefreshVersion] = React.useState(0);
  const refresh = React.useCallback(() => setRefreshVersion((v) => v + 1), []);

  // Candidate base runs: every task except this one. Newest first, so the default
  // selection is the most recent other run.
  React.useEffect(() => {
    let disposed = false;
    async function loadTasks() {
      try {
        const result = await api.tasks();
        if (disposed) return;
        const others = result.tasks
          .filter((t) => t.id !== taskId)
          .sort((a, b) => (b.created_unix ?? 0) - (a.created_unix ?? 0));
        setCandidates(others);
        setError("");
      } catch (e) {
        if (!disposed) setError((e as Error).message);
      }
    }
    void loadTasks();
    return () => {
      disposed = true;
    };
  }, [taskId]);

  // Default to the most recent other run once the list arrives.
  React.useEffect(() => {
    if (!baseId && candidates.length > 0) {
      setBaseId(candidates[0].id);
    }
  }, [baseId, candidates]);

  React.useEffect(() => {
    if (!baseId) {
      setLoading(false);
      setDiff(null);
      return;
    }
    let disposed = false;
    async function load() {
      setLoading(true);
      try {
        const result = await api.taskDiff(taskId, baseId);
        if (disposed) return;
        setDiff(result);
        setError("");
      } catch (e) {
        if (!disposed) {
          setError((e as Error).message);
          setDiff(null);
        }
      } finally {
        if (!disposed) setLoading(false);
      }
    }
    void refreshVersion;
    void load();
    return () => {
      disposed = true;
    };
  }, [taskId, baseId, refreshVersion]);

  const totalTracked = diff
    ? diff.new.length + diff.persisting.length + diff.resolved.length + diff.regressed.length
    : 0;

  return (
    <div className="flex flex-col gap-4">
      {error ? (
        <Alert variant="destructive">
          <AlertDescription>
            Failed to compare runs: {error}
            <Button variant="outline" size="sm" onClick={refresh}>
              Retry
            </Button>
          </AlertDescription>
        </Alert>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle>Compare with an earlier run</CardTitle>
          <CardDescription>
            Findings are matched by identity — vulnerability class, affected assets and location — not by their title or
            summary, which vary between runs even when nothing changed.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap items-center gap-3">
          <label className="text-sm font-medium" htmlFor="diff-base">
            Base run
          </label>
          <select
            id="diff-base"
            className="border-input bg-background h-9 min-w-64 rounded-md border px-3 text-sm"
            value={baseId}
            onChange={(e) => setBaseId(e.target.value)}
            disabled={candidates.length === 0}
          >
            {candidates.length === 0 ? <option value="">No other runs available</option> : null}
            {candidates.map((t) => (
              <option key={t.id} value={t.id}>
                {t.name?.trim() || t.description?.trim() || t.id}
              </option>
            ))}
          </select>
          <Button variant="outline" size="sm" onClick={refresh} disabled={!baseId}>
            <RefreshCwIcon data-icon="inline-start" />
            Recompare
          </Button>
          {diff ? (
            <span className="text-muted-foreground text-xs">
              {totalTracked} tracked
              {diff.untracked > 0 ? ` · ${diff.untracked} without a stable identity` : ""}
            </span>
          ) : null}
        </CardContent>
      </Card>

      {loading && !diff ? <Skeleton className="h-64 w-full" /> : null}

      {!loading && candidates.length === 0 ? (
        <Empty>
          <EmptyHeader>
            <EmptyTitle>Nothing to compare against</EmptyTitle>
            <EmptyDescription>
              A comparison needs a second run of the same target. Scan it again and its findings will be comparable here.
            </EmptyDescription>
          </EmptyHeader>
        </Empty>
      ) : null}

      {diff ? (
        <>
          {/* The honesty banner: the head run's coverage decides whether "resolved" is
              proof or merely an absence of evidence. */}
          {!diff.resolved_trustworthy ? (
            <Alert variant="destructive">
              <AlertTriangleIcon />
              <AlertTitle>Resolved is unproven for this comparison</AlertTitle>
              <AlertDescription>
                {diff.resolved_note ||
                  "The current run did not cover its scope completely, so a finding missing from it may simply be untested rather than fixed."}
              </AlertDescription>
            </Alert>
          ) : null}

          {diff.untracked > 0 ? (
            <Alert>
              <AlertDescription>
                {diff.untracked} finding{diff.untracked === 1 ? "" : "s"} had no stable identity (no vulnerability class
                and no location), so {diff.untracked === 1 ? "it is" : "they are"} excluded from the comparison rather
                than being reported as new on every run.
              </AlertDescription>
            </Alert>
          ) : null}

          <div className="grid gap-4 lg:grid-cols-2">
            {BUCKETS.map((bucket) => {
              const entries = diff[bucket.key];
              // The resolved bucket is the one whose meaning depends on coverage; say so
              // on the card itself, not only in the top banner.
              const unproven = bucket.key === "resolved" && !diff.resolved_trustworthy;
              return (
                <Card key={bucket.key} className="min-w-0">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      {bucket.title}
                      <span className="text-muted-foreground text-sm font-normal">{entries.length}</span>
                    </CardTitle>
                    <CardDescription>{bucket.description}</CardDescription>
                  </CardHeader>
                  <CardContent className="flex flex-col gap-2">
                    {entries.length === 0 ? (
                      <p className="text-muted-foreground text-sm">Nothing in this bucket.</p>
                    ) : null}
                    {entries.map((entry) => (
                      <div
                        key={entry.fingerprint}
                        className="flex flex-wrap items-center justify-between gap-2 rounded-md border px-3 py-2"
                      >
                        <span className="min-w-0 flex-1 break-words text-sm" title={entryLabel(entry)}>
                          {entryLabel(entry)}
                        </span>
                        <span className="flex shrink-0 flex-wrap items-center gap-2">
                          <StatusBadge domain="severity" value={entry.severity} dot />
                          {unproven ? (
                            <span className="text-muted-foreground text-xs">unproven</span>
                          ) : (
                            <StatusBadge domain="finding" value={entry.status} dot />
                          )}
                        </span>
                      </div>
                    ))}
                  </CardContent>
                </Card>
              );
            })}
          </div>

          <div className="text-muted-foreground flex flex-wrap gap-4 text-xs">
            <span>Earlier run covered its scope: {diff.base_complete ? "yes" : "no"}</span>
            <span>This run covered its scope: {diff.head_complete ? "yes" : "no"}</span>
          </div>
        </>
      ) : null}
    </div>
  );
}
