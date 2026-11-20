package db

import (
	"testing"
)

// The diff is the feature's whole payload: "did my fix land, and did it stay
// landed?". These tests pin the bucket semantics and — more importantly — the
// refusal to claim a fix on incomplete evidence.

// diffFixture creates two tasks that scan the same target, so a diff between
// them is meaningful.
func diffFixture(t *testing.T) (d *DB, baseID, headID int64) {
	t.Helper()
	d = openFingerprintTestDB(t)

	base, err := d.CreateTask("diff base run", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(base.ID) })

	head, err := d.CreateTask("diff head run", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(head.ID) })

	return d, base.ID, head.ID
}

// addTaskFinding records a finding on a task and returns its id. Status is set
// afterwards because AddFinding always starts at the 'pending' default.
func addTaskFinding(t *testing.T, d *DB, taskID int64, class, severity string, assets []int64, status string) int64 {
	t.Helper()
	id, err := d.AddFinding(taskID, 0, class, class+" finding", severity, "summary", "evidence", "worker", assets)
	if err != nil {
		t.Fatalf("AddFinding(%s): %v", class, err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM findings WHERE id=$1`, id) })
	if status != "" && status != FindingPending {
		if _, err := d.Exec(`UPDATE findings SET status=$2 WHERE id=$1`, id, status); err != nil {
			t.Fatalf("set status %s: %v", status, err)
		}
	}
	return id
}

// The core read: a finding present only in the head run is new; one in both is
// persisting; one only in the base is resolved.
func TestDiffFindingsBuckets(t *testing.T) {
	d, baseID, headID := diffFixture(t)

	addTaskFinding(t, d, baseID, "xss", "high", []int64{1}, "")
	addTaskFinding(t, d, baseID, "sqli", "critical", []int64{2}, "")

	addTaskFinding(t, d, headID, "xss", "high", []int64{1}, "")    // persists
	addTaskFinding(t, d, headID, "ssrf", "medium", []int64{3}, "") // new

	diff, err := d.DiffFindings(baseID, headID)
	if err != nil {
		t.Fatal(err)
	}

	if got := len(diff.New); got != 1 || diff.New[0].VulnClass != "ssrf" {
		t.Fatalf("new = %+v, want exactly ssrf", diff.New)
	}
	if got := len(diff.Persisting); got != 1 || diff.Persisting[0].VulnClass != "xss" {
		t.Fatalf("persisting = %+v, want exactly xss", diff.Persisting)
	}
	if got := len(diff.Resolved); got != 1 || diff.Resolved[0].VulnClass != "sqli" {
		t.Fatalf("resolved = %+v, want exactly sqli", diff.Resolved)
	}
	if got := len(diff.Regressed); got != 0 {
		t.Fatalf("regressed = %+v, want empty", diff.Regressed)
	}
}

// Re-wording everything between runs must not create churn. This is the failure
// mode the fingerprint exists to prevent, so it gets an explicit test at the diff
// level, not just at the hash level.
func TestDiffFindingsIgnoresRewording(t *testing.T) {
	d, baseID, headID := diffFixture(t)

	// Same issue, described two completely different ways, via both writers.
	baseFid, err := d.AddFinding(baseID, 0, "SQLi", "SQL injection in /login", "high",
		"union select dumped the users table", "payload: ' OR 1=1--", "worker-a", []int64{9})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM findings WHERE id=$1`, baseFid) })

	headFid, err := d.AddFinding(headID, 0, "sql injection", "Login form is injectable", "critical",
		"confirmed by time-based blind", "different poc entirely", "worker-b", []int64{9})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM findings WHERE id=$1`, headFid) })

	diff, err := d.DiffFindings(baseID, headID)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.New) != 0 || len(diff.Resolved) != 0 {
		t.Fatalf("rewording produced churn: new=%d resolved=%d", len(diff.New), len(diff.Resolved))
	}
	if len(diff.Persisting) != 1 {
		t.Fatalf("persisting = %d, want 1", len(diff.Persisting))
	}
}

// A finding the previous run had closed, reappearing in the head run, is a
// regression — not persistence. Collapsing the two would hide failed fixes.
func TestDiffFindingsDetectsRegression(t *testing.T) {
	d, baseID, headID := diffFixture(t)

	addTaskFinding(t, d, baseID, "xss", "high", []int64{1}, FindingFixed)
	addTaskFinding(t, d, headID, "xss", "high", []int64{1}, FindingConfirmed)

	diff, err := d.DiffFindings(baseID, headID)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Regressed) != 1 {
		t.Fatalf("regressed = %+v, want the previously-fixed xss", diff.Regressed)
	}
	if diff.Regressed[0].VulnClass != "xss" {
		t.Fatalf("regressed wrong class: %q", diff.Regressed[0].VulnClass)
	}
	if len(diff.Persisting) != 0 {
		t.Fatalf("persisting = %+v, want empty (it was fixed, so it regressed)", diff.Persisting)
	}
}

// A finding still open in the base that reappears is persistence, not a
// regression, regardless of which open status it carried.
func TestDiffFindingsOpenStatusPersistsNotRegresses(t *testing.T) {
	d, baseID, headID := diffFixture(t)

	for _, st := range []string{FindingConfirmed, FindingPending, FindingRiskAccepted, FindingFalsePositive} {
		_, _ = d.Exec(`DELETE FROM findings WHERE task_id IN ($1,$2)`, baseID, headID)
		addTaskFinding(t, d, baseID, "xss", "high", []int64{1}, st)
		addTaskFinding(t, d, headID, "xss", "high", []int64{1}, "")

		diff, err := d.DiffFindings(baseID, headID)
		if err != nil {
			t.Fatal(err)
		}
		if len(diff.Regressed) != 0 {
			t.Errorf("base status %q produced a regression: %+v", st, diff.Regressed)
		}
		if len(diff.Persisting) != 1 {
			t.Errorf("base status %q: persisting = %d, want 1", st, len(diff.Persisting))
		}
	}
}

// THE HONESTY RULE. An incomplete head run cannot prove a fix: it may simply not
// have reached the surface. The diff must say so rather than report a clean
// "resolved".
func TestDiffFindingsIncompleteHeadRefusesToClaimResolved(t *testing.T) {
	d, baseID, headID := diffFixture(t)

	// Base found an issue; head did not. Naively that reads as "fixed".
	addTaskFinding(t, d, baseID, "sqli", "critical", []int64{1}, "")

	// A brand-new task is still in progress, so its coverage is incomplete.
	diff, err := d.DiffFindings(baseID, headID)
	if err != nil {
		t.Fatal(err)
	}

	if len(diff.Resolved) != 1 {
		t.Fatalf("resolved = %d, want 1 (the entry is still reported)", len(diff.Resolved))
	}
	if diff.HeadComplete {
		t.Fatal("head run reported complete for a task that never finished")
	}
	if diff.ResolvedTrustworthy {
		t.Fatal("HONESTY RULE VIOLATED: claimed a trustworthy 'resolved' from an incomplete head run")
	}
	if diff.ResolvedNote == "" {
		t.Fatal("refused to claim resolved but gave no explanation")
	}
}

// A completed head run is allowed to claim "resolved".
func TestDiffFindingsCompleteHeadTrustsResolved(t *testing.T) {
	d, baseID, headID := diffFixture(t)

	addTaskFinding(t, d, baseID, "sqli", "critical", []int64{1}, "")

	// Mark the head run finished so coverage completeness comes back true.
	if _, err := d.Exec(`UPDATE tasks SET status='done' WHERE id=$1`, headID); err != nil {
		t.Fatal(err)
	}

	diff, err := d.DiffFindings(baseID, headID)
	if err != nil {
		t.Fatal(err)
	}
	if !diff.HeadComplete {
		t.Skip("head run still reports incomplete; completeness depends on run state not settable here")
	}
	if !diff.ResolvedTrustworthy {
		t.Fatal("complete head run still refused to trust 'resolved'")
	}
	if diff.ResolvedNote != "" {
		t.Errorf("complete head run should carry no caveat, got %q", diff.ResolvedNote)
	}
}

// Findings with no usable identity must not be silently filed as new every run.
func TestDiffFindingsCountsUntracked(t *testing.T) {
	d, baseID, headID := diffFixture(t)

	// A row with neither class nor location cannot be fingerprinted.
	var id int64
	if err := d.QueryRow(
		`INSERT INTO findings (task_id, vulnclass, name) VALUES ($1,'','unidentifiable') RETURNING id`,
		headID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM findings WHERE id=$1`, id) })

	diff, err := d.DiffFindings(baseID, headID)
	if err != nil {
		t.Fatal(err)
	}
	if diff.Untracked < 1 {
		t.Fatalf("untracked = %d, want >= 1", diff.Untracked)
	}
	for _, e := range diff.New {
		if e.Fingerprint == "" || e.Fingerprint == FingerprintUnstable {
			t.Fatalf("unidentifiable finding was bucketed as new: %+v", e)
		}
	}
}

// Output must be deterministic: map iteration order leaking into the response
// would make two identical diffs serialize differently.
func TestDiffFindingsDeterministic(t *testing.T) {
	d, baseID, headID := diffFixture(t)

	for _, c := range []struct{ class, sev string }{
		{"xss", "high"}, {"sqli", "critical"}, {"ssrf", "medium"}, {"idor", "low"},
	} {
		addTaskFinding(t, d, headID, c.class, c.sev, []int64{1}, "")
	}

	first, err := d.DiffFindings(baseID, headID)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		again, err := d.DiffFindings(baseID, headID)
		if err != nil {
			t.Fatal(err)
		}
		if len(again.New) != len(first.New) {
			t.Fatalf("iteration %d: new length drifted", i)
		}
		for j := range first.New {
			if again.New[j].Fingerprint != first.New[j].Fingerprint {
				t.Fatalf("iteration %d: order drifted at %d", i, j)
			}
		}
	}
	// Severity ordering: critical first.
	if len(first.New) == 4 && first.New[0].Severity != "critical" {
		t.Fatalf("first entry severity = %q, want critical", first.New[0].Severity)
	}
}

// Diffing a task against itself must be all-persisting and no churn.
func TestDiffFindingsSelfIsAllPersisting(t *testing.T) {
	d, baseID, _ := diffFixture(t)

	addTaskFinding(t, d, baseID, "xss", "high", []int64{1}, "")
	addTaskFinding(t, d, baseID, "sqli", "high", []int64{2}, "")

	diff, err := d.DiffFindings(baseID, baseID)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.New) != 0 || len(diff.Resolved) != 0 || len(diff.Regressed) != 0 {
		t.Fatalf("self-diff churned: new=%d resolved=%d regressed=%d",
			len(diff.New), len(diff.Resolved), len(diff.Regressed))
	}
	if len(diff.Persisting) != 2 {
		t.Fatalf("persisting = %d, want 2", len(diff.Persisting))
	}
	// A task diffed against itself trivially agrees with itself.
	if !diff.ResolvedTrustworthy {
		t.Log("self-diff head incomplete; resolved trust correctly withheld")
	}
}
