package db

import (
	"context"
	"testing"
)

// The unit tests pin what FindingFingerprint computes. These pin that the value
// survives the round trip: the column exists on an upgraded database, both
// write paths populate it, and the diff can look a finding up by it.
//
// Every test opens the live PostgreSQL the rest of the db suite uses and skips
// when it is unreachable, matching db/findings_test.go.

func openFingerprintTestDB(t *testing.T) *DB {
	t.Helper()
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

// deleteFindings removes exactly the rows a test created, so a shared database
// is left as it was found.
func deleteFindings(t *testing.T, d *DB, ids ...int64) {
	t.Helper()
	t.Cleanup(func() {
		for _, id := range ids {
			_, _ = d.Exec(`DELETE FROM findings WHERE id=$1`, id)
		}
	})
}

// The point of the whole feature: two runs describing the same issue in
// different words must produce the same stored identity.
func TestFindingFingerprintPersistedOnInsert(t *testing.T) {
	d := openFingerprintTestDB(t)
	ctx := context.Background()

	// Same class, different spelling; same assets, different order; entirely
	// different model-authored prose.
	a, err := d.AddFinding(0, 0, "SQLi", "SQL injection in login", "high",
		"union select returned rows", "payload: ' OR 1=1--", "worker-1", []int64{11, 22})
	if err != nil {
		t.Fatalf("AddFinding: %v", err)
	}
	deleteFindings(t, d, a)

	b, err := d.AddFinding(0, 0, "sql_injection", "SQLi (login)", "critical",
		"different prose entirely", "different poc", "worker-2", []int64{22, 11})
	if err != nil {
		t.Fatalf("AddFinding: %v", err)
	}
	deleteFindings(t, d, b)

	var fpA, fpB string
	if err := d.QueryRowContext(ctx, `SELECT fingerprint FROM findings WHERE id=$1`, a).Scan(&fpA); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRowContext(ctx, `SELECT fingerprint FROM findings WHERE id=$1`, b).Scan(&fpB); err != nil {
		t.Fatal(err)
	}

	if fpA == "" {
		t.Fatal("fingerprint was not persisted")
	}
	if fpA != fpB {
		t.Fatalf("two descriptions of one finding got different identities: %q != %q", fpA, fpB)
	}
	if want := FindingFingerprint("sqli", []int64{11, 22}, ""); fpA != want {
		t.Fatalf("stored %q, want %q", fpA, want)
	}
}

// Prose must not influence identity. If it did, every re-scan would look like
// total churn — the exact failure the feature exists to prevent.
func TestFindingFingerprintIgnoresProse(t *testing.T) {
	d := openFingerprintTestDB(t)
	ctx := context.Background()

	rows := []struct{ name, summary, evidence string }{
		{"SQL injection", "union select returned rows", "payload A"},
		{"Completely different title", "a summary written by another model", "payload B"},
		{"", "", ""}, // even an empty description
	}
	var first string
	for i, r := range rows {
		id, err := d.AddFinding(0, 0, "sqli", r.name, "medium", r.summary, r.evidence, "w", []int64{5})
		if err != nil {
			t.Fatalf("row %d: %v", i, err)
		}
		deleteFindings(t, d, id)

		var fp string
		if err := d.QueryRowContext(ctx, `SELECT fingerprint FROM findings WHERE id=$1`, id).Scan(&fp); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = fp
			continue
		}
		if fp != first {
			t.Fatalf("row %d prose changed identity: %q != %q", i, fp, first)
		}
	}
}

// A fingerprint that never varies is worse than none: it would make the diff
// claim every finding persists forever. Distinct issues must separate.
func TestFindingFingerprintDistinguishesIssues(t *testing.T) {
	d := openFingerprintTestDB(t)
	ctx := context.Background()

	cases := []struct {
		class string
		asset int64
	}{
		{"xss", 101},
		{"sqli", 101},
		{"xss", 102},
	}
	seen := map[string]string{}
	for _, c := range cases {
		id, err := d.AddFinding(0, 0, c.class, "n", "low", "s", "e", "w", []int64{c.asset})
		if err != nil {
			t.Fatal(err)
		}
		deleteFindings(t, d, id)

		var fp string
		if err := d.QueryRowContext(ctx, `SELECT fingerprint FROM findings WHERE id=$1`, id).Scan(&fp); err != nil {
			t.Fatal(err)
		}
		if prev, dup := seen[fp]; dup {
			t.Fatalf("%s on asset %d collided with %s", c.class, c.asset, prev)
		}
		seen[fp] = c.class
	}
	if len(seen) != len(cases) {
		t.Fatalf("expected %d distinct identities, got %d", len(cases), len(seen))
	}
}

// The index is partial (fingerprint <> ”), which is exactly the predicate the
// diff filters on. Prove the lookup returns the right row.
func TestFindingsFingerprintLookup(t *testing.T) {
	d := openFingerprintTestDB(t)
	ctx := context.Background()

	id, err := d.AddFinding(0, 0, "xss", "reflected", "medium", "s", "e", "w", []int64{7})
	if err != nil {
		t.Fatal(err)
	}
	deleteFindings(t, d, id)

	want := FindingFingerprint("xss", []int64{7}, "")
	var n int
	if err := d.QueryRowContext(ctx, `SELECT count(*) FROM findings WHERE fingerprint=$1`, want).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("fingerprint lookup returned %d rows, want 1", n)
	}
}

// The migration is ADD COLUMN ... NOT NULL DEFAULT ”, so a pre-existing writer
// that does not know about fingerprints must still succeed and store ” rather
// than NULL. A NULL would break every later query that compares fingerprints.
func TestFingerprintColumnDefaultsToEmpty(t *testing.T) {
	d := openFingerprintTestDB(t)
	ctx := context.Background()

	var id int64
	if err := d.QueryRowContext(ctx,
		`INSERT INTO findings (vulnclass, name) VALUES ('xss','legacy shape') RETURNING id`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	deleteFindings(t, d, id)

	var stored *string
	if err := d.QueryRowContext(ctx, `SELECT fingerprint FROM findings WHERE id=$1`, id).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == nil {
		t.Fatal("fingerprint is NULL; the column must default to the empty string")
	}
	if *stored != "" {
		t.Fatalf("legacy insert got %q, want empty", *stored)
	}
}

// The transactional writer (exploration.RecordFinding) is a second, independent
// INSERT site. It resolves assets through exploration_anchors, so it is the one
// path where a real asset row is required — and where a mismatch between the two
// writers would hide.
func TestRecordFindingPersistsFingerprint(t *testing.T) {
	d := openFingerprintTestDB(t)
	ctx := context.Background()

	tk, err := d.CreateTask("fingerprint transactional test", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(tk.ID) })

	assets := d.Assets()
	a1, err := assets.UpsertRootDomain(UpsertRootDomainReq{Domain: "fp-record-test.example", TaskID: tk.ID})
	if err != nil {
		t.Fatalf("asset 1: %v", err)
	}
	a2, err := assets.UpsertRootDomain(UpsertRootDomainReq{Domain: "fp-record-test2.example", TaskID: tk.ID})
	if err != nil {
		t.Fatalf("asset 2: %v", err)
	}

	es := d.Exploration(tk.ExplorationID)
	out, err := es.RecordFinding(ctx, RecordFindingInput{
		TaskID:        tk.ID,
		ExplorationID: tk.ExplorationID,
		VulnClass:     "cross_site_scripting",
		Name:          "reflected XSS",
		Severity:      "high",
		Summary:       "payload echoed into the page",
		Evidence:      "<script>alert(1)</script>",
		Worker:        "worker-tx",
		// Deliberately the reverse of the order the fingerprint will sort into.
		AssetIDs: []int64{a2, a1},
	})
	if err != nil {
		t.Fatalf("RecordFinding: %v", err)
	}
	deleteFindings(t, d, out.FindingID)

	var fp string
	if err := d.QueryRowContext(ctx, `SELECT fingerprint FROM findings WHERE id=$1`, out.FindingID).Scan(&fp); err != nil {
		t.Fatal(err)
	}

	// canonicalVulnClass folds cross_site_scripting onto xss, so this must equal
	// what the other writer produces for the same issue.
	want := FindingFingerprint("xss", []int64{a1, a2}, "")
	if fp != want {
		t.Fatalf("transactional writer stored %q, want %q", fp, want)
	}
	if fp == "" || fp == FingerprintUnstable {
		t.Fatalf("transactional writer produced no usable identity: %q", fp)
	}
}
