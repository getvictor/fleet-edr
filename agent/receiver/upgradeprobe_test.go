package receiver

import "testing"

// TestParseNEUpgradePending pins the systemextensionsctl-output parsing that distinguishes a staged upgrade (a previous NE
// version "waiting to uninstall on reboot") from every other state, so the agent only emits the reboot-required hint when a
// reboot is genuinely the fix (#399). The marker must land on a line that also names OUR network-extension bundle.
func TestParseNEUpgradePending(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		output string
		want   bool
	}{
		{
			name: "staged upgrade: old version waiting to uninstall on reboot",
			output: "2 extension(s)\n" +
				"--- com.apple.system_extension.network_extension\n" +
				"enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n" +
				"*\t*\tFDG8Q7N4CC\tcom.fleetdm.edr.networkextension (0.2.1/1)\tFleet EDR Network Extension\t[activated enabled]\n" +
				"\t*\tFDG8Q7N4CC\tcom.fleetdm.edr.networkextension (0.1.1/1)\tnetworkextension\t[terminated waiting to uninstall on reboot]\n",
			want: true,
		},
		{
			name: "single active version: no pending uninstall",
			output: "1 extension(s)\n" +
				"*\t*\tFDG8Q7N4CC\tcom.fleetdm.edr.networkextension (0.2.1/1)\tFleet EDR Network Extension\t[activated enabled]\n",
			want: false,
		},
		{
			name: "not approved yet: NE present but no reboot marker",
			output: "1 extension(s)\n" +
				"\t\tFDG8Q7N4CC\tcom.fleetdm.edr.networkextension (0.2.1/1)\tFleet EDR Network Extension\t[activated waiting for user]\n",
			want: false,
		},
		{
			name: "a different vendor's NE waiting to uninstall must not match",
			output: "1 extension(s)\n" +
				"\t*\tOTHERTEAM\tcom.othervendor.networkextension (1.0/1)\tOther\t[terminated waiting to uninstall on reboot]\n",
			want: false,
		},
		{
			name:   "empty output",
			output: "",
			want:   false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := parseNEUpgradePending(tc.output, neExtensionBundleID); got != tc.want {
				t.Fatalf("parseNEUpgradePending = %v, want %v", got, tc.want)
			}
		})
	}
}
