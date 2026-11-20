package db

import (
	"encoding/json"
	"sort"
	"strings"
)

// FindingDiffEntry is one finding as it appears in a diff bucket. It carries the
// fingerprint so a caller can join back to either run, plus enough to render a
// row without a second round trip.
type FindingDiffEntry struct {
	Fingerprint string  `json:"fingerprint"`
	VulnClass   string  `json:"vulnclass"`
	Name        string  `json:"name"`
	Severity    string  `json:"severity"`
	Status      string  `json:"status"`
	FindingID   int64   `json:"finding_id"`
	AssetIDs    []int64 `json:"asset_ids"`
}

// FindingDiff compares a base run with a head run.
//
// The four buckets are disjoint and cover every finding that carries a usable
// fingerprint. Findings with none (FingerprintUnstable, or a row written before
// the column existed and not yet backfilled) are counted in Untracked and appear
// in no bucket: pretending an unidentifiable finding is "new" every run is the
// churn this feature exists to eliminate.
type FindingDiff struct {
	BaseTaskID int64 `json:"base_task_id"`
	HeadTaskID int64 `json:"head_task_id"`

	New        []FindingDiffEntry `json:"new"`
	Persisting []FindingDiffEntry `json:"persisting"`
	Resolved   []FindingDiffEntry `json:"resolved"`
	Regressed  []FindingDiffEntry `json:"regressed"`

	// BaseComplete and HeadComplete are each run's coverage verdict. They are
	// reported so a reader can see why a number should not be trusted yet.
	BaseComplete bool `json:"base_complete"`
	HeadComplete bool `json:"head_complete"`

	// ResolvedTrustworthy is false unless the head run covered its scope. A scan
	// that stopped early did not fail to find the issue; it never looked. With an
	// incomplete head, "resolved" is an absence of evidence and must be presented
	// as one. This fails closed, the way verification withholds a verdict it
	// cannot support.
	ResolvedTrustworthy bool   `json:"resolved_trustworthy"`
	ResolvedNote        string `json:"resolved_note,omitempty"`

	// Untracked counts findings on either side with no usable identity.
	Untracked int `json:"untracked"`
}

// closedStatuses are the dispositions that claim the issue is no longer live. If
// one of these reappears in the head run, the fix did not hold and the bucket is
// "regressed" rather than "persisting" — the distinction is the whole point of
// running the same target twice.
func closedStatuses(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case FindingFixed, FindingResolved:
		return true
	}
	return false
}

// DiffFindings compares the findings of two tasks that scanned the same target.
// Direction is base → head; either may be the older run.
//
// Matching is on the fingerprint alone. Name, summary, severity and report body
// are model-authored and vary between runs on an identical target, so none of
// them may influence identity — otherwise every re-scan would look like total
// churn.
func (d *DB) DiffFindings(baseTaskID, headTaskID int64) (*FindingDiff, error) {
	base, err := d.taskFindingsForDiff(baseTaskID)
	if err != nil {
		return nil, err
	}
	head, err := d.taskFindingsForDiff(headTaskID)
	if err != nil {
		return nil, err
	}

	diff := &FindingDiff{
		BaseTaskID: baseTaskID,
		HeadTaskID: headTaskID,
		New:        []FindingDiffEntry{},
		Persisting: []FindingDiffEntry{},
		Resolved:   []FindingDiffEntry{},
		Regressed:  []FindingDiffEntry{},
		Untracked:  base.untracked + head.untracked,
	}

	for fp, h := range head.byFingerprint {
		if b, seen := base.byFingerprint[fp]; seen {
			// The issue was known. If the previous run had closed it, its presence
			// again means the fix did not hold.
			if closedStatuses(b.Status) {
				diff.Regressed = append(diff.Regressed, entryOf(h))
			} else {
				diff.Persisting = append(diff.Persisting, entryOf(h))
			}
			continue
		}
		diff.New = append(diff.New, entryOf(h))
	}
	for fp, b := range base.byFingerprint {
		if _, stillThere := head.byFingerprint[fp]; stillThere {
			continue
		}
		diff.Resolved = append(diff.Resolved, entryOf(b))
	}

	// Deterministic output: map iteration order must never reach an API response
	// or a signed bundle.
	sortDiffEntries(diff.New)
	sortDiffEntries(diff.Persisting)
	sortDiffEntries(diff.Resolved)
	sortDiffEntries(diff.Regressed)

	baseCov, err := d.Assets().CoverageLedger(baseTaskID)
	if err != nil {
		return nil, err
	}
	headCov, err := d.Assets().CoverageLedger(headTaskID)
	if err != nil {
		return nil, err
	}
	diff.BaseComplete = baseCov.Completeness != nil && baseCov.Completeness.Complete
	diff.HeadComplete = headCov.Completeness != nil && headCov.Completeness.Complete

	diff.ResolvedTrustworthy = diff.HeadComplete
	if !diff.HeadComplete {
		diff.ResolvedNote = "The head run did not cover its scope completely, so a missing finding may simply be untested. Treat 'resolved' as unproven until a complete run confirms it."
		if headCov.Completeness != nil && headCov.Completeness.Caveat != "" {
			diff.ResolvedNote += " " + headCov.Completeness.Caveat
		}
	}
	return diff, nil
}

func entryOf(f *DBFinding) FindingDiffEntry {
	assets := f.AssetIDs
	if assets == nil {
		assets = []int64{}
	}
	return FindingDiffEntry{
		Fingerprint: f.Fingerprint,
		VulnClass:   f.VulnClass,
		Name:        f.Name,
		Severity:    f.Severity,
		Status:      f.Status,
		FindingID:   f.ID,
		AssetIDs:    assets,
	}
}

// sortDiffEntries orders by severity (critical first), then class, then
// fingerprint, so two identical diffs serialize byte-for-byte the same.
func sortDiffEntries(entries []FindingDiffEntry) {
	rank := func(s string) int {
		switch strings.ToLower(strings.TrimSpace(s)) {
		case SeverityCritical:
			return 4
		case SeverityHigh:
			return 3
		case SeverityMedium:
			return 2
		case SeverityLow:
			return 1
		}
		return 0
	}
	sort.SliceStable(entries, func(i, j int) bool {
		ri, rj := rank(entries[i].Severity), rank(entries[j].Severity)
		if ri != rj {
			return ri > rj
		}
		if entries[i].VulnClass != entries[j].VulnClass {
			return entries[i].VulnClass < entries[j].VulnClass
		}
		return entries[i].Fingerprint < entries[j].Fingerprint
	})
}

// taskFindings is one side of a diff, keyed by fingerprint.
type taskFindings struct {
	byFingerprint map[string]*DBFinding
	untracked     int
}

// taskFindingsForDiff loads one task's findings keyed by fingerprint. Rows with
// no usable identity are counted, not bucketed.
//
// A fingerprint can legitimately appear more than once (the same issue proven on
// two runs of the same surface, or a duplicate row). The earliest row by id wins
// so the choice is stable across calls; the bucket semantics do not change.
func (d *DB) taskFindingsForDiff(taskID int64) (*taskFindings, error) {
	rows, err := d.Query(`
		SELECT f.id, f.vulnclass, COALESCE(f.name, ''), f.severity,
		       COALESCE(f.status, 'pending'), COALESCE(f.fingerprint, ''), f.asset_ids
		FROM findings f
		WHERE f.task_id = $1
		ORDER BY f.id`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := &taskFindings{byFingerprint: map[string]*DBFinding{}}
	for rows.Next() {
		f := &DBFinding{}
		var aidsJSON string
		if err := rows.Scan(&f.ID, &f.VulnClass, &f.Name, &f.Severity, &f.Status, &f.Fingerprint, &aidsJSON); err != nil {
			return nil, err
		}
		if f.Fingerprint == "" || f.Fingerprint == FingerprintUnstable {
			out.untracked++
			continue
		}
		if _, dup := out.byFingerprint[f.Fingerprint]; dup {
			continue
		}
		_ = json.Unmarshal([]byte(aidsJSON), &f.AssetIDs)
		out.byFingerprint[f.Fingerprint] = f
	}
	return out, rows.Err()
}
