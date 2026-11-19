package db

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
)

// fingerprintVersion is part of every fingerprint value. It is bumped whenever
// the canonicalisation below changes in a way that alters existing values, so a
// churned identity is visible in the data instead of silently re-bucketing every
// finding on the next run.
const fingerprintVersion = "v1"

// FingerprintUnstable is stored instead of a fingerprint when a finding has
// neither a class nor a location to key on. Such findings are bucketed
// separately by the diff rather than being given an invented identity: a diff
// that admits "I cannot tell" is survivable, one that guesses is not.
const FingerprintUnstable = "unstable"

// FindingFingerprint derives the cross-run identity of a finding.
//
// The inputs are deliberately narrow. Only three things enter the hash:
//
//	vulnclass  the vulnerability class, canonicalised
//	assetIDs   the assets the finding was proven on, sorted so the order the
//	           caller happened to use cannot change the identity
//	location   the surface (path/parameter) the finding was proven at
//
// Nothing else may be added. In particular the human-readable name, the
// summary, the severity and the report body must never enter this hash: they
// are model-authored and vary between runs on identical targets, so including
// them would make every re-scan look like total churn — the exact failure this
// feature exists to prevent.
//
// The result is "v1:<16 hex chars>", or FingerprintUnstable when there is
// nothing stable to key on.
func FindingFingerprint(vulnclass string, assetIDs []int64, location string) string {
	class := canonicalVulnClass(vulnclass)
	loc := strings.ToLower(NormalizeCoverageField(location))
	if class == "" && loc == "" {
		return FingerprintUnstable
	}

	// Sort a copy: callers pass slices that may be shared, and sorting in place
	// would mutate the caller's data.
	ids := make([]int64, len(assetIDs))
	copy(ids, assetIDs)
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	var b strings.Builder
	b.Grow(32 + len(class) + len(loc) + 12*len(ids))
	b.WriteString(class)
	b.WriteByte(0x1f)
	for i, id := range ids {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.FormatInt(id, 10))
	}
	b.WriteByte(0x1f)
	b.WriteString(loc)

	sum := sha256.Sum256([]byte(b.String()))
	return fingerprintVersion + ":" + hex.EncodeToString(sum[:])[:16]
}
