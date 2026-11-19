package db

import (
	"strings"
	"testing"
)

// The fingerprint is the gate on the whole continuous-proof feature: if it
// churns between runs, every re-scan looks like total churn and the diff
// destroys the trust it exists to build. These tests pin the properties that
// matter, not just the current output.
func TestFindingFingerprintStability(t *testing.T) {
	// The same finding, described the way three different workers would
	// describe it, must land on one identity. Note the spelling variety in
	// vulnclass and the casing/whitespace in location.
	a := FindingFingerprint("SQLi", []int64{7, 3}, "/api/login")
	b := FindingFingerprint("sql_injection", []int64{3, 7}, "/API/Login")
	c := FindingFingerprint("SQL injection", []int64{7, 3}, "  /api/login  ")

	if a != b || b != c {
		t.Fatalf("same finding produced %d identities: %q / %q / %q", 3, a, b, c)
	}
}

// Asset order must never matter: the agent reports assets in whatever order it
// happened to discover them.
func TestFindingFingerprintAssetOrderIndependent(t *testing.T) {
	orders := [][]int64{{1, 2, 3}, {3, 2, 1}, {2, 1, 3}, {3, 1, 2}}
	want := FindingFingerprint("xss", orders[0], "/search")
	for _, order := range orders {
		if got := FindingFingerprint("xss", order, "/search"); got != want {
			t.Fatalf("asset order %v changed identity: %q != %q", order, got, want)
		}
	}
}

// Duplicate and nil asset ids are the same thing: the finding was proven
// without a resolvable asset.
func TestFindingFingerprintNilAndEmptyAssetsAgree(t *testing.T) {
	if a, b := FindingFingerprint("xss", nil, "/q"), FindingFingerprint("xss", []int64{}, "/q"); a != b {
		t.Fatalf("nil vs empty assets differ: %q != %q", a, b)
	}
}

// A different location on the same class and asset is a different finding.
func TestFindingFingerprintLocationSeparates(t *testing.T) {
	a := FindingFingerprint("xss", []int64{1}, "/search")
	b := FindingFingerprint("xss", []int64{1}, "/profile")
	if a == b {
		t.Fatal("two different surfaces collapsed to one identity")
	}
}

// A different class on the same surface is a different finding.
func TestFindingFingerprintClassSeparates(t *testing.T) {
	a := FindingFingerprint("xss", []int64{1}, "/q")
	b := FindingFingerprint("sqli", []int64{1}, "/q")
	if a == b {
		t.Fatal("two different classes collapsed to one identity")
	}
}

// A different asset is a different finding even with identical class/location:
// the same bug on two hosts must be trackable separately.
func TestFindingFingerprintAssetSeparates(t *testing.T) {
	a := FindingFingerprint("xss", []int64{1}, "/q")
	b := FindingFingerprint("xss", []int64{2}, "/q")
	if a == b {
		t.Fatal("same bug on two assets collapsed to one identity")
	}
}

// With nothing stable to key on, the fingerprint must say so rather than invent
// an identity that will not reproduce.
func TestFindingFingerprintUnstableWhenNothingToKeyOn(t *testing.T) {
	for _, tc := range []struct {
		name     string
		class    string
		location string
	}{
		{"both empty", "", ""},
		{"whitespace only", "   ", "\t\n "},
	} {
		if got := FindingFingerprint(tc.class, []int64{5}, tc.location); got != FingerprintUnstable {
			t.Errorf("%s: got %q, want %q", tc.name, got, FingerprintUnstable)
		}
	}
}

// A class with no location is still a usable identity (the class alone is
// stable for asset-wide findings), and so is a location with no class.
func TestFindingFingerprintPartialInputsAreUsable(t *testing.T) {
	classOnly := FindingFingerprint("sqli", []int64{1}, "")
	locOnly := FindingFingerprint("", []int64{1}, "/api/login")
	for _, got := range []string{classOnly, locOnly} {
		if got == FingerprintUnstable {
			t.Errorf("partial input was treated as unstable: %q", got)
		}
	}
	if classOnly == locOnly {
		t.Error("class-only and location-only collapsed to one identity")
	}
}

// The shape is load-bearing: the version prefix lets a canonicalisation change
// be detected in the data instead of silently re-bucketing every finding.
func TestFindingFingerprintShape(t *testing.T) {
	got := FindingFingerprint("xss", []int64{1}, "/q")
	if !strings.HasPrefix(got, fingerprintVersion+":") {
		t.Fatalf("missing version prefix: %q", got)
	}
	hexPart := strings.TrimPrefix(got, fingerprintVersion+":")
	if len(hexPart) != 16 {
		t.Fatalf("hex length = %d, want 16 (%q)", len(hexPart), got)
	}
	for _, r := range hexPart {
		if !strings.ContainsRune("0123456789abcdef", r) {
			t.Fatalf("non-hex rune %q in %q", r, got)
		}
	}
}

// Fingerprints must be stable across processes: no map iteration order, no
// time, no randomness. Recomputing the same input many times proves the
// function is pure.
func TestFindingFingerprintDeterministic(t *testing.T) {
	want := FindingFingerprint("idor", []int64{9, 4, 6}, "/orders/{id}")
	for i := 0; i < 100; i++ {
		if got := FindingFingerprint("idor", []int64{9, 4, 6}, "/orders/{id}"); got != want {
			t.Fatalf("iteration %d drifted: %q != %q", i, got, want)
		}
	}
}
