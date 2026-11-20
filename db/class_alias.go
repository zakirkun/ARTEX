package db

import "strings"

// canonicalVulnClass folds a vulnclass to the class token the knowledge corpus
// defines, so one class spelled several ways is one identity.
//
// This is a stopgap. The corpus lives in the knowledge package, which is on the
// unmerged feat/airecon-knowledge-and-skills branch and not on main. Until that
// lands, the tables in vulnclass_table.go (generated from the corpus, so they
// agree with it) do the same work here.
//
// When the knowledge package arrives, replace the body with:
//
//	return knowledge.Class(v)
//
// and delete vulnclass_table.go. Callers do not change.
//
// Unknown input is not an error: it falls back to its normalised form, so a
// typo'd class groups with itself rather than scattering across the diff.
func canonicalVulnClass(v string) string {
	n := normClassToken(v)
	if n == "" {
		return ""
	}
	if canonicalVulnClasses[n] {
		return n
	}
	if target, ok := vulnClassAliases[n]; ok {
		return target
	}
	return n
}

// normClassToken lowercases and collapses every run of non-alphanumerics to a
// single underscore, matching the corpus normaliser so "SQL injection",
// "sql-injection" and "sql_injection" all become sql_injection before any
// table lookup happens.
func normClassToken(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	prevSep := true // trims a leading separator
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevSep = false
		default:
			if !prevSep {
				b.WriteByte('_')
				prevSep = true
			}
		}
	}
	return strings.TrimSuffix(b.String(), "_")
}
