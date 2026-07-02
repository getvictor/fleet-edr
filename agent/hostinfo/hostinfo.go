// Package hostinfo collects the host's self-reported identity for the inventory block of the status check-in (issue #579): the kernel
// hostname and the macOS product identity from SystemVersion.plist. Collection is pure Go with no external processes; a field whose
// source is unavailable is returned empty rather than failing, so a dev container or a stripped test environment still produces a
// postable report.
package hostinfo

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"os"
)

// systemVersionPath is where macOS records the product identity. Present on every macOS install; absent anywhere else, which the
// collector treats as "no OS metadata" rather than an error.
const systemVersionPath = "/System/Library/CoreServices/SystemVersion.plist"

// Info is the collected host identity. Zero-valued fields mean the source was unavailable.
type Info struct {
	Hostname  string
	OSName    string // ProductName, e.g. "macOS"
	OSVersion string // ProductVersion, e.g. "26.4"
	OSBuild   string // ProductBuildVersion, e.g. "25E123"
}

// Collect gathers the host identity from the running system.
func Collect() Info {
	return collect(systemVersionPath)
}

// collect is the testable core: the SystemVersion.plist path is a parameter so tests use a fixture.
func collect(plistPath string) Info {
	info := Info{}
	if h, err := os.Hostname(); err == nil {
		info.Hostname = h
	}
	buf, err := os.ReadFile(plistPath) // #nosec G304 -- fixed system path in production; parameterized only for tests.
	if err != nil {
		return info
	}
	kv, err := parseStringPlist(buf)
	if err != nil {
		return info
	}
	info.OSName = kv["ProductName"]
	info.OSVersion = kv["ProductVersion"]
	info.OSBuild = kv["ProductBuildVersion"]
	return info
}

// parseStringPlist extracts the top-level key -> string pairs from an XML plist. The same minimal-plist idiom as the enrollment
// package's persisted-token reader: a flat dict of <key>/<string> pairs, no nesting, no arrays, decoded with encoding/xml so no plist
// dependency is added. Non-string values are skipped.
func parseStringPlist(buf []byte) (map[string]string, error) {
	dec := xml.NewDecoder(bytes.NewReader(buf))
	kv := map[string]string{}
	var key string
	for {
		tok, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return kv, nil
			}
			return nil, err
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch se.Name.Local {
		case "key":
			if err := dec.DecodeElement(&key, &se); err != nil {
				return nil, err
			}
		case "string":
			var v string
			if err := dec.DecodeElement(&v, &se); err != nil {
				return nil, err
			}
			if key != "" {
				kv[key] = v
				key = ""
			}
		default:
			// A non-string value type (integer, array, dict): the pending key does not apply to it.
			key = ""
		}
	}
}
