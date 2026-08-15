package catalog

import "github.com/fleetdm/edr/server/rules/api"

// Platforms attestations for the catalog. Every rule in the current catalog targets macOS: they key on launchd, dyld, osascript,
// Keychain, and sudoers tradecraft (ADR-0018). The api.Rule interface requires Platforms(), so this attestation is compile-enforced;
// the catalog guard test asserts each set is non-empty and valid. Declaring the methods here keeps the platform attestation for the
// whole catalog in one place instead of scattered across the rule struct definitions. DNSC2Beacon is portable in principle, but it
// stays darwin-only until a Windows agent emits dns_query events; Phase 2 of Windows support re-scopes it then.

func (*SuspiciousExec) Platforms() []api.Platform         { return []api.Platform{api.PlatformDarwin} }
func (*PersistenceLaunchAgent) Platforms() []api.Platform { return []api.Platform{api.PlatformDarwin} }
func (*DyldInsert) Platforms() []api.Platform             { return []api.Platform{api.PlatformDarwin} }
func (*ShellFromOffice) Platforms() []api.Platform        { return []api.Platform{api.PlatformDarwin} }
func (*OsascriptNetworkExec) Platforms() []api.Platform   { return []api.Platform{api.PlatformDarwin} }
func (*CredentialKeychainDump) Platforms() []api.Platform { return []api.Platform{api.PlatformDarwin} }
func (*PrivilegeLaunchdPlistWrite) Platforms() []api.Platform {
	return []api.Platform{api.PlatformDarwin}
}
func (*SudoersTamper) Platforms() []api.Platform           { return []api.Platform{api.PlatformDarwin} }
func (*ApplicationControlBlock) Platforms() []api.Platform { return []api.Platform{api.PlatformDarwin} }
func (*DNSC2Beacon) Platforms() []api.Platform             { return []api.Platform{api.PlatformDarwin} }
func (*SensorTamper) Platforms() []api.Platform            { return []api.Platform{api.PlatformDarwin} }
func (*SensorRecoveryFailed) Platforms() []api.Platform    { return []api.Platform{api.PlatformDarwin} }
