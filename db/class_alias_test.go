package db

import "testing"

// The alias table is generated from the knowledge corpus, which is not on main
// yet. These tests pin the behaviour the fingerprint depends on, so that when
// knowledge.Class replaces this stopgap the contract is already written down.
func TestCanonicalVulnClassFoldsSpellings(t *testing.T) {
	cases := []struct{ in, want string }{
		{"SQLi", "sql_injection"},
		{"sqli", "sql_injection"},
		{"SQL injection", "sql_injection"},
		{"sql_injection", "sql_injection"},
		{"sql-injection", "sql_injection"},
		{"  SQL  Injection  ", "sql_injection"},
		{"XSS", "xss"},
		{"cross_site_scripting", "xss"},
		{"RCE", "command_injection"},
		{"LFI", "lfi"}, // lfi is its own class in the corpus, not an alias of path_traversal
		{"IDOR", "idor"},
		{"SSRF", "ssrf"},
		{"XXE", "xxe"},
	}
	for _, c := range cases {
		if got := canonicalVulnClass(c.in); got != c.want {
			t.Errorf("canonicalVulnClass(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// An unrecognised class must not vanish: it groups with itself. Losing it would
// silently drop findings out of the diff.
func TestCanonicalVulnClassKeepsUnknown(t *testing.T) {
	const unknown = "some_novel_thing"
	if got := canonicalVulnClass(unknown); got != unknown {
		t.Fatalf("unknown class = %q, want it preserved as %q", got, unknown)
	}
	// Normalisation still applies, so two spellings of an unknown class agree.
	if a, b := canonicalVulnClass("Novel Thing"), canonicalVulnClass("novel_thing"); a != b {
		t.Fatalf("unknown class spellings diverged: %q != %q", a, b)
	}
}

func TestCanonicalVulnClassEmpty(t *testing.T) {
	for _, in := range []string{"", "   ", "\t\n", "---", "___"} {
		if got := canonicalVulnClass(in); got != "" {
			t.Errorf("canonicalVulnClass(%q) = %q, want empty", in, got)
		}
	}
}

// Every alias must point at a real canonical class; a dangling target would
// mean the generated table and the corpus disagreed.
func TestAliasTargetsAreCanonical(t *testing.T) {
	for alias, target := range vulnClassAliases {
		if !canonicalVulnClasses[target] {
			t.Errorf("alias %q points at %q, which is not a canonical class", alias, target)
		}
	}
}

// A canonical class must never also appear as an alias key, or the table would
// contradict itself depending on lookup order.
func TestNoCanonicalIsAlsoAlias(t *testing.T) {
	for class := range canonicalVulnClasses {
		if _, dup := vulnClassAliases[class]; dup {
			t.Errorf("class %q is both canonical and an alias", class)
		}
	}
}

// The corpus defines 77 classes; guard against a truncated or mangled table.
func TestCanonicalClassTableIsPopulated(t *testing.T) {
	if len(canonicalVulnClasses) < 70 {
		t.Fatalf("only %d canonical classes; table looks truncated", len(canonicalVulnClasses))
	}
	if len(vulnClassAliases) < 150 {
		t.Fatalf("only %d aliases; table looks truncated", len(vulnClassAliases))
	}
}
