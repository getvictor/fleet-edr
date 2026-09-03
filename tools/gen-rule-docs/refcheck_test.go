//go:build refcheck

package main

import (
	"net/url"
	"testing"
)

// Throwaway probe (build-tagged off) answering two questions before the reference renderer is tightened: does re-serialising a URL
// neutralise a markdown payload, and do the corpus's real citations survive re-serialisation unchanged?
func TestRefCheckProbe(t *testing.T) {
	for _, s := range []string{
		"https://safe.example/a ![pixel](https://attacker.example/pixel)",
		"https://safe.example/x`code`",
		"https://safe.example/a<b>c",
	} {
		u, _ := url.Parse(s)
		t.Logf("INJECTION %-62q -> %q", s, u.String())
	}
	var total, bad int
	for _, r := range allRegisteredRules() {
		for _, ref := range r.Doc.References {
			total++
			u, err := url.Parse(ref)
			if err != nil || u.String() != ref {
				bad++
				t.Logf("DIFFERS %q", ref)
			}
		}
	}
	t.Logf("%d references, %d do not round-trip", total, bad)
}
