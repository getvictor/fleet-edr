package api

import "testing"

func TestIsValidPlatform(t *testing.T) {
	t.Parallel()
	cases := []struct {
		platform string
		want     bool
	}{
		{PlatformDarwin, true},
		{PlatformWindows, true},
		{PlatformLinux, true},
		{"", false},
		{"Darwin", false},
		{"beos", false},
		{"windows ", false},
	}
	for _, tc := range cases {
		t.Run(tc.platform, func(t *testing.T) {
			t.Parallel()
			if got := IsValidPlatform(tc.platform); got != tc.want {
				t.Fatalf("IsValidPlatform(%q) = %v, want %v", tc.platform, got, tc.want)
			}
		})
	}
}

func TestNormalizePlatform(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want string
	}{
		{"", PlatformDarwin},
		{PlatformDarwin, PlatformDarwin},
		{PlatformWindows, PlatformWindows},
		{PlatformLinux, PlatformLinux},
		// NormalizePlatform does not validate; a caller checks IsValidPlatform first. An already-rejected value passes through
		// unchanged, which documents that normalize is only the empty-to-darwin mapping.
		{"beos", "beos"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			if got := NormalizePlatform(tc.in); got != tc.want {
				t.Fatalf("NormalizePlatform(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
