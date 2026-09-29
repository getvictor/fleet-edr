import Foundation

/// TccNames spells a TCC modification's Endpoint Security enums (ESTypes.h) as the wire names `tcc_modify` carries (issue #1185), so
/// the server reads a stable word rather than an SDK ordinal. A value this build does not know is "unknown", which the schema
/// allows, so an SDK that adds a case degrades to a named gap rather than a wrong name.
///
/// Pure Foundation over raw values, so it is unit-testable without EndpointSecurity; ESFSubscriber+TCC passes the rawValue of each
/// field.
enum TccNames {
    /// identityType names es_tcc_identity_type_t: how the identity string names the app the permission is about.
    static func identityType(_ raw: UInt32) -> String {
        name(raw, in: identityTypes)
    }

    /// updateType names es_tcc_event_type_t: whether the record was created, modified or deleted.
    static func updateType(_ raw: UInt32) -> String {
        name(raw, in: updateTypes)
    }

    /// right names es_tcc_authorization_right_t: the permission the record holds after the change.
    static func right(_ raw: UInt32) -> String {
        name(raw, in: rights)
    }

    /// reason names es_tcc_authorization_reason_t: why the record changed, as a user answering a prompt or an MDM policy.
    static func reason(_ raw: UInt32) -> String {
        name(raw, in: reasons)
    }

    /// name is the case raw numbers in a table of the SDK's cases, or "unknown" past its end.
    private static func name(_ raw: UInt32, in cases: [String]) -> String {
        cases.indices.contains(Int(raw)) ? cases[Int(raw)] : "unknown"
    }

    /// identityTypes, updateTypes, rights and reasons are the SDK's cases in the order they are numbered, from zero.
    private static let identityTypes = ["bundle_id", "executable_path", "policy_id", "file_provider_domain_id"]
    private static let updateTypes = ["unknown", "create", "modify", "delete"]
    private static let rights = ["denied", "unknown", "allowed", "limited", "add_modify_added", "session_pid", "learn_more"]
    private static let reasons = [
        "none", "error", "user_consent", "user_set", "system_set", "service_policy", "mdm_policy", "service_override_policy",
        "missing_usage_string", "prompt_timeout", "preflight_unknown", "entitled", "app_type_policy", "prompt_cancel"
    ]
}
